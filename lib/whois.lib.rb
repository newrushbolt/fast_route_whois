$lib_name=File.basename(__FILE__,".rb")
$lib_dir=File.expand_path(File.dirname(__FILE__))

require 'etc'
require 'mysql2'
require 'ipaddr'
require 'rubygems'
require 'json'

require "#{$lib_dir}/../etc/common.conf.rb"
if File.exists?("#{$lib_dir}/etc/#{$lib_name}.conf.rb")
	require "#{$lib_dir}/etc/#{$lib_name}.conf.rb"
end

$private_ip_nets=[]
$private_nets.each do |net|
	$private_ip_nets.push(IPAddr.new(net))
	$err_logger.debug "Loading private IP-net #{net}"
end

#Class with common whois functions
class Common_whois
	protected
	
#Initialize Mysql2 instance
	def initialize
		begin
			@whois_db_client = Mysql2::Client.new(:host => $whois_db_host, :database => $whois_db, :username => $whois_db_user, :password => $whois_db_pass)
		rescue  => e_cor
			$err_logger.fatal "Cannot connect to DB:\n :host => #{$whois_db_host}, :database => #{$whois_db}, :username => #{$whois_db_user}, :password => #{$whois_db_pass}"
			$err_logger.fatal e_cor.inspect
		end
	end
	
	public
	
	def is_correct(ip)
		begin
			IPAddr.new(ip)
			$private_ip_nets.each do |net|
				if net.include?(ip)
					$err_logger.warn "IP #{ip} is in private net #{net.inspect}, exiting"
					return false
				end
			end
			return true
		rescue  => e_cor
			$err_logger.error "#{ip} is not a correct IP"
			$err_logger.error e_cor.to_s
			return false
		end
	end
end

#Fast whois route lookup, using MySQL fast_inetnums(MEMORY) table
class Fast_whois < Common_whois

	protected

	def get_info(ip)
		$err_logger.debug "Started <@get_fast_whois_info> for #{ip}"
		info_result = {}
		req="select inet_ntoa(network) as network, inet_ntoa(netmask) as netmask,asn from #{$whois_db_fast_inetnums_table}
	where (inet_aton(\"#{ip}\") & netmask) = network and network !=0 and netmask != 0;"
		$err_logger.debug req
		res=@whois_db_client.query(req)
		$err_logger.debug "Got SQl results:"
		$err_logger.debug res.each
		if res.any?
			result=res.first
			info_result["network"]=result["network"]
			info_result["netmask"]=result["netmask"]
			info_result["asn"]=result["asn"]
		end
		
		if ! info_result.empty? and info_result["network"] and info_result["netmask"] and info_result["asn"]
			$err_logger.debug "Got full info for #{ip} :"
			$err_logger.debug info_result.to_s
		else
			$err_logger.warn "Cannot get info for #{ip} :"
			$err_logger.warn info_result.to_s
			info_result=nil
		end
		
		return info_result
	end
	

	
	public
#Return a _Hash_ with ip route information or _nil_
#==== Examples
#	>get_ip_route(8.8.8.8)
#	{"network"=>"8.8.8.0", "netmask"=>"255.255.255.0", "asn"=>15169}
#	Hash
#
#	>get_ip_route(10.11.23.1)
#	
#	NilClass
	def get_ip_route(ip)
		if is_correct(ip) == false
			return nil
		end
		res=get_info(ip)
		if ! res
			$err_logger.warn "Cannot get whois for #{ip}"
		end
		return res
	end
	
#Check if fast tables got same info as slow	
	def check_fast_table
		$err_logger.debug "Checking fast table content"
		begin
			req="select (select count(*) as fcnt from #{$whois_db_fast_inetnums_table}) = (select count(*) as cnt from #{$whois_db_fast_inetnums_table}) as fast_table_ok;"
			$err_logger.debug req
			res=$whois_db_client.query(req)
		rescue => e
			$err_logger.error "Error comparing inetnums tables"
			$err_logger.error req
			$err_logger.error e.to_s
			return false
		end
		
		if res.first["fast_table_ok"] == 1
			$err_logger.debug "Fast_inetnums(MEMORY) got same route count as inetnums(INNODB)"
			return true
		else
			$err_logger.warn "Fast_inetnums(MEMORY) havent got enought routes
			#, updating from inetnums(INNODB)"
			return false
		end
	end
	
#Load all route from slow table to fast table(needed only after MySQL restart)
	def load_slow2fast
		begin
			req="insert ignore into #{$whois_db_fast_inetnums_table} (select * from #{$whois_db_fast_inetnums_table});"
			res=$whois_db_client.query(req)
		rescue => e
			$err_logger.error "Error while updating fast_inetnums table"
			$err_logger.error req
			$err_logger.error e.to_s
			return false
		end
	end
	
end


#Slow whois route lookup, using online-whois and GeoIPASNum
#
#Will update info to fast_inetnums
class Slow_whois < Common_whois
	
	protected
	
#Init Superclass init by calling anything from it and load WHOIS and GeoIP objects
	def initialize
		super.inspect
		require 'geoip'
		require 'whois'
		@whois_client = Whois::Client.new
		@geo_client=GeoIP.new("#{$lib_dir}/../var/geoip/GeoIPASNum.dat")
	end

	def get_lacnic_route(inetnum)
		$err_logger.debug inetnum
		ip_all=inetnum.match(/(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){0,2}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/[0-9]{1,2}/)[0]
		ip_part=ip_all.split("/")[0]
		net_part=ip_all.split("/")[1]
		net=nil
		if ip_part.match(/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){2}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/)
			net="#{ip_part}.0/#{net_part}"
		elsif ip_part.match(/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){1}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/)
			net="#{ip_part}.0.0/#{net_part}"
		elsif ip_part.match(/^(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/)
			net="#{ip_part}.0.0.0/#{net_part}"
		end
		$err_logger.debug "Should be #{net}"	
		return net
	end
	
	def get_krnic_route(inetnum)
		$err_logger.debug inetnum
		ip_all=inetnum.match(/IPv4 Address[ ]*\:[ ]*[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}[ ]*\-[ ]*[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}[ ]*\(\/[0-9]{1,2}\)/)[0]
		ip_part=ip_all.match(/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/)[0]
		net_part=ip_all.match(/\/[0-9]{1,2}/)[0]
		net="#{ip_part}#{net_part}"
		$err_logger.debug "Should be #{net}"	
		return net
	end

	def get_asn_geo(ip)
		$err_logger.debug "Got no ASN for #{ip}, trying geoip base"
		begin
			geo_info=@geo_client.asn(ip)
			asn=geo_info[:number].gsub(/^*(AS|as|As|aS)/, "").to_i
		rescue  => e
			$err_logger.error "Error in GeoIPASNum request for #{ip}"
			$err_logger.error e.to_s
			return nil
		end
		$err_logger.debug "Got asn: #{asn}"
		$err_logger.debug asn
		return asn
	end
	
	def inetnum2cidr(inetnum_raw)
		$err_logger.debug "Parsing inetnum \"#{inetnum_raw}\" to CIDR"
		begin
			inetnum=inetnum_raw.match(/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\-[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/)[0]
			first_ip=inetnum.split("-")[0]
			last_ip=inetnum.split("-")[1]
			netmask=[]
			for num in (0..3)
				first=first_ip.split(".")[num].to_i
				last=last_ip.split(".")[num].to_i
				octet=255-(last - first)
				netmask.push(octet)
			end
		rescue => e 
			$err_logger.warn "Cannot parse inetnum \"#{inetnum_raw}\" to CIDR"
		end
		$err_logger.debug "Parsed inetnum \"#{inetnum_raw}\" to CIDR #{inetnum.split("-")[0]}/#{netmask.join(".")}"
		return "#{inetnum.split("-")[0]}/#{netmask.join(".")}"
	end
	
	def get_info(ip)
		$err_logger.debug "Started <get_whois_info> for #{ip}"
		info_result = {}
		begin
			whois_result=@whois_client.lookup(ip).to_s
		rescue  => e
			$err_logger.error "Error while geting whois info for #{ip}"
			$err_logger.error e.to_s
			return nil
		end
		$err_logger.debug "Got whois response for #{ip} :"
		$err_logger.debug whois_result
		if whois_result
			is_lacnic=false
			is_krnic=false
			whois_result.split("\n").each do |whois_result_line|
				begin
					if whois_result_line.start_with?("% Joint Whois - whois.lacnic.net")
						$err_logger.debug "It's a LACNIC inetnum"
						is_lacnic=true
					end
					if whois_result_line.start_with?("KRNIC is not an ISP but a National Internet Registry similar to APNIC.")
						$err_logger.debug "It's a KRNIC inetnum"
						is_krnic=true
					end
					if is_lacnic and whois_result_line.start_with?("inetnum:")
						$err_logger.debug "Found LACNIC inetnum, parsing"
						lacnic_route=get_lacnic_route(whois_result_line)
						ip_obj=IPAddr.new(lacnic_route,Socket::AF_INET)
						$err_logger.debug ip_obj.inspect
						info_result["network"]=ip_obj.to_s
						info_result["netmask"]=ip_obj.inspect.gsub(/^\#.*\//,"").delete(">")
					elsif whois_result_line.start_with?("inetnum:")
						$err_logger.debug "Found backup inetnum, parsing"
						backup_inetnum=inetnum2cidr(whois_result_line.delete(" "))
						ip_obj=IPAddr.new(backup_inetnum,Socket::AF_INET)
						$err_logger.debug ip_obj.inspect
						info_result["backup_network"]=ip_obj.to_s
						info_result["backup_netmask"]=ip_obj.inspect.gsub(/^\#.*\//,"").delete(">")
					end
					if is_krnic and whois_result_line.start_with?("IPv4 Address")
						$err_logger.debug "Found KRNIC inetnum, parsing"
						krnic_route=get_krnic_route(whois_result_line)
						ip_obj=IPAddr.new(krnic_route,Socket::AF_INET)
						$err_logger.debug ip_obj.inspect
						info_result["network"]=ip_obj.to_s
						info_result["netmask"]=ip_obj.inspect.gsub(/^\#.*\//,"").delete(">")
					end
					if whois_result_line.start_with?("origin")
						$err_logger.debug "Found Origin(ASN) line:"
						$err_logger.debug whois_result_line
						info_result["asn"]=whois_result_line.gsub(/^origin\:[w| ]*(AS|as|As|aS)/, "").to_i
					end
					if whois_result_line.start_with?("CIDR")
						$err_logger.debug "Found CIDR(route) line:"
						$err_logger.debug whois_result_line
						ip_obj_a=whois_result_line.gsub(/^CIDR\:[w| ]*/, "").match(/^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\/[0-9]{1,2}[, ]{0,3}){1,10}/)[0].delete(" ").split(",").sort
						$err_logger.debug ip_obj_a
						ip_obj=IPAddr.new(ip_obj_a[0])
						info_result["network"]=ip_obj.to_s
						info_result["netmask"]=ip_obj.inspect.gsub(/^\#.*\//,"").delete(">")
					end
					if whois_result_line.start_with?("route")
						$err_logger.debug "Found route line:"
						$err_logger.debug whois_result_line
						ip_obj=IPAddr.new(whois_result_line.gsub(/^route\:[w| ]*/, ""))
						info_result["network"]=ip_obj.to_s
						info_result["netmask"]=ip_obj.inspect.gsub(/^\#.*\//,"").delete(">")
					end
				rescue => e
					$err_logger.error "Cannot parse whois line for #{ip} :"
					$err_logger.error whois_result_line
				end
			end
		end
		$err_logger.debug info_result.to_s
		
		if ! info_result["network"] and ! info_result["netmask"] and info_result["backup_network"] and info_result["backup_netmask"]
			info_result["network"] = info_result["backup_network"]
			info_result["netmask"] = info_result["backup_netmask"]
		end

		if info_result["backup_network"] and info_result["backup_netmask"]
			info_result.delete("backup_netmask")
			info_result.delete("backup_network")
		end
		
		if info_result["network"] and info_result["netmask"] and ! info_result["asn"]
			info_result["asn"]=get_asn_geo(ip)
		end
		if info_result["network"] and info_result["netmask"] and info_result["asn"]
			$err_logger.debug "Got full info for #{ip} :"
			$err_logger.debug info_result.to_s
		else
			$err_logger.error "Cannot get info for #{ip}, inserting null record :"
			$err_logger.error info_result.to_s
			info_result={ :network => "0.0.0.0",:asn => 0, :netmask => "0.0.0.0" }
		end
		return info_result
	end

	public
#Inserts an route info into DB
#==== Examples
#	>inetnum2db({"network"=>"8.8.8.0", "netmask"=>"255.255.255.0", "asn"=>15169})
	def inetnum2db(inetnum)
		$err_logger.debug "Inserting update fo DB:\n#{inetnum}"
		begin
			req="insert ignore into #{$whois_db_inetnums_table} values (inet_aton(\"#{inetnum["network"]}\"),inet_aton(\"#{inetnum["netmask"]}\"),#{inetnum["asn"]});"
			$err_logger.debug req
			res=@whois_db_client.query(req)
			return true
		rescue  => e
			$err_logger.error "Error while updating fast_whois info for #{inetnum.to_s}"
			$err_logger.error req.to_s
			$err_logger.error e.to_s
			return false
		end
	end

#Return a _Hash_ with ip route information or _nil_
#==== Examples
#	>get_ip_route(8.8.8.8)
#	{"network"=>"8.8.8.0", "netmask"=>"255.255.255.0", "asn"=>15169}
#	Hash
#
#	>get_ip_route(10.11.23.1)
#	
#	NilClass
	def get_ip_route(ip)
		begin
			if is_correct(ip) == false
				return nil
			end			
			res=get_info(ip)
			if ! res
				$err_logger.warn "Cannot get slow_whois for #{ip}"
			else
				inetnum2db(res)
			end
		rescue  => e_main
			$err_logger.error "Error while geting whois info for #{ip}"
			$err_logger.error e_main.to_s
			return nil
		end
		return res
	end

end

