
$my_dir=File.expand_path(File.dirname(__FILE__))
require "#{$my_dir}/config.rb"
require 'etc'
require 'geoip'
require 'json'
require 'logger'
require 'mysql2'
require 'rubygems'
require 'ruby-prof'
require 'whois'
$err_logger=Logger.new("#{$my_dir}/var/log/functions.lib.log")
$err_logger.level=Logger::ERROR

if ARGV[0]
    case ARGV[0]
    when 'debug'
	$err_logger.level=Logger::DEBUG
    when 'info'
	$err_logger.level=Logger::IFNO
    when 'warn'
	$err_logger.level=Logger::WARN
    when 'error'
	$err_logger.level=Logger::ERROR
    when 'fatal'
	$err_logger.level=Logger::FATAL
    end
end

$whois_db_client = nil
$private_ip_nets=[]
$private_nets.each do |net|
	$private_ip_nets.push(IPAddr.new(net))
	$err_logger.debug "Loading private IP-net #{net}"
end

def get_whois_info(aton)
	$err_logger.debug "Started <get_whois_info> for #{aton}"
    info_result = {}
    begin
		whois_client = Whois::Client.new
        whois_result= whois_client.lookup(aton).to_s
    rescue  => e
        $err_logger.error "Error while geting whois info for #{aton}"
        $err_logger.error e.to_s
        return nil
    end
	# $err_logger.debug "Got whois response for #{aton} :"
	# $err_logger.debug whois_result
    if whois_result
        whois_result.split("\n").each do |whois_result_line|
			begin
				if whois_result_line.start_with?("origin")
					$err_logger.debug "Found Origin(ASN) line:"
					$err_logger.debug whois_result_line
					info_result["asn"]=whois_result_line.gsub(/^origin\:[w| ]*(AS|as|As|aS)/, "").to_i
				end
				if whois_result_line.start_with?("CIDR")
					$err_logger.debug "Found CIDR(route) line:"
					$err_logger.debug whois_result_line
					ip_obj=IPAddr.new(whois_result_line.gsub(/^CIDR\:[w| ]*/, ""))
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
				$err_logger.error "Cannot parse whois line for #{aton} :"
				$err_logger.error whois_result_line
			end
        end
    end
	if info_result["network"] and info_result["netmask"] and ! info_result["asn"]
		$err_logger.debug "Got no ASN for #{aton}, trying geoip base"
		geo_info=GeoIP.new("#{$my_dir}/GeoIPASNum.dat").asn(aton)
		asn=geo_info[:number].gsub(/^*(AS|as|As|aS)/, "").to_i
		info_result["asn"]=asn
		$err_logger.debug "Got asn: #{asn}"
		$err_logger.debug asn
	end
	if info_result["network"] and info_result["netmask"] and info_result["asn"]
		$err_logger.debug "Got full info for #{aton} :"
		$err_logger.debug info_result.to_s
	else
		$err_logger.debug "Cannot get info for #{aton} :"
		$err_logger.debug info_result.to_s
		info_result=nil
	end
	return info_result
end

def get_fast_whois_info(aton)
	$err_logger.debug "Started <get_fast_whois_info> for #{aton}"
    info_result = {}
    
	req="select inet_ntoa(network) as network, inet_ntoa(netmask) as netmask,asn from #{$whois_db_inetnums_table}
where (inet_aton(\"#{aton}\") & netmask) = network;"
	res=$whois_db_client.query(req)
	
	info_result["network"]=res["network"]
	info_result["netmask"]=res["netmask"]
	info_result["asn"]=res["asn"]
			
	if info_result["network"] and info_result["netmask"] and ! info_result["asn"]
		$err_logger.debug "Got no ASN for #{aton}, trying geoip base"
		geo_info=GeoIP.new("#{$my_dir}/GeoIPASNum.dat").asn(aton)
		asn=geo_info[:number].gsub(/^*(AS|as|As|aS)/, "").to_i
		info_result["asn"]=asn
		$err_logger.debug "Got asn: #{asn}"
		$err_logger.debug asn
	end
	if info_result["network"] and info_result["netmask"] and info_result["asn"]
		$err_logger.debug "Got full info for #{aton} :"
		$err_logger.debug info_result.to_s
	else
		$err_logger.debug "Cannot get info for #{aton} :"
		$err_logger.debug info_result.to_s
		info_result=nil
	end
	return info_result
end

def get_info(aton)
	begin
			IPAddr.new(aton)
			$private_ip_nets.each do |net|
				if net.include?(aton)
					$err_logger.error "IP #{aton} is in private net #{net.inspect}, exiting"
					return nil
				end
			end
			rest=get_whois_info(aton)
	rescue  => e
			$err_logger.error "Error while geting whois info for #{aton}"
			$err_logger.error e.to_s
			return nil
	end
	return true
end