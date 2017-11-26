$lib_dir=File.expand_path(File.dirname(__FILE__))
#$err_logger.info "Loading config from #{$lib_dir}/config.rb"
$private_ip_nets=[]
$private_nets.each do |net|
	$private_ip_nets.push(IPAddr.new(net))
	$err_logger.debug "Loading private IP-net #{net}"
end

def i_geocity_client
	begin
		db_path="#{$my_dir}/GeoLiteCity.dat"
		$err_logger.debug "Trying to load geoip DB from: #{db_path}"
		@geocity_client=GeoIP.new(db_path)
	rescue => e_main
		$err_logger.error e_main.to_s
		$err_logger.error "Error while starting GeoIP client"
	end
end


def get_geo_info(network)
	geo_out={}
	$err_logger.debug "Getting GeoIP info"
	begin
		geo_info=@geocity_client.city(network)
	rescue => e
		$err_logger.warn "Error in GeoIP for #{network}"
		$err_logger.warn e.to_s
	end

	if geo_info and geo_info.country_code3 and geo_info.country_code3 != ''
		geo_out["country"]="#{geo_info.country_code3}"
	else
		$err_logger.warn "GeoIP for #{network} doesn't have country_code3 info"
		geo_out["country"]=''
	end
	if geo_info and geo_info.real_region_name and geo_info.real_region_name != ''
		geo_out["region"]="#{geo_info.real_region_name}"
	else
		$err_logger.warn "GeoIP for #{network} doesn't have real_region_name info"
		geo_out["region"]=''
	end
	if geo_info and geo_info.city_name and geo_info.city_name != ''
		geo_out["city"]="#{geo_info.city_name}"
	else
		$err_logger.warn "GeoIP for #{network} doesn't have city_name info"
		geo_out["city"]=''
	end
	return geo_out
end


def check_fast_table
	$err_logger.debug "Checking fast table content"
	begin
		req="select (select count(*) as fcnt from #{$whois_db_fast_inetnums_table}) = (select count(*) as cnt from #{$whois_db_inetnums_table}) as fast_table_ok;"
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
		$err_logger.warn "Fast_inetnums(MEMORY) havent got enought routes, updating from inetnums(INNODB)"
		begin
			req="insert ignore into #{$whois_db_fast_inetnums_table} (select * from #{$whois_db_inetnums_table});"
			res=$whois_db_client.query(req)
		rescue => e
			$err_logger.error "Error while updating fast_inetnums table"
			$err_logger.error req
			$err_logger.error e.to_s
			return false
		end
		return true
	end
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

def get_asn_geo(aton)
	$err_logger.debug "Got no ASN for #{aton}, trying geoip base"
	begin
		geo_info=GeoIP.new("#{$lib_dir}/GeoIPASNum.dat").asn(aton)
		asn=geo_info[:number].gsub(/^*(AS|as|As|aS)/, "").to_i
	rescue  => e
		$err_logger.error "Error in GeoIPASNum request for #{aton}"
		$err_logger.error e.to_s
		return nil
	end
	$err_logger.debug "Got asn: #{asn}"
	$err_logger.debug asn
	return asn
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
		is_lacnic=false
        whois_result.split("\n").each do |whois_result_line|
			begin
				if whois_result_line.start_with?("% Joint Whois - whois.lacnic.net")
					$err_logger.debug "It's a LACNIC inetnum"
					is_lacnic=true
				end
				if is_lacnic and whois_result_line.start_with?("inetnum:")
					$err_logger.debug "Found LACNIC inetnum, parsing"
					lacnic_route=get_lacnic_route(whois_result_line)
					ip_obj=IPAddr.new(lacnic_route,Socket::AF_INET)
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
	$err_logger.debug info_result.to_s

	if info_result["network"] and info_result["netmask"] and ! info_result["asn"]
		info_result["asn"]=get_asn_geo(aton)
	end
	if info_result["network"] and info_result["netmask"] and info_result["asn"]
		$err_logger.debug "Got full info for #{aton} :"
		$err_logger.debug info_result.to_s
	else
		$err_logger.error "Cannot get info for #{aton} :"
		$err_logger.error info_result.to_s
		info_result=nil
	end
	return info_result
end

