$my_dir=File.expand_path(File.dirname(__FILE__))

require 'logger'
require "#{$my_dir}/config.rb"

$err_logger=Logger.new("#{$my_dir}/inetnums_update.log")
$err_logger.level=$log_level
if ARGV[1]
    case ARGV[1]
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

require "#{$my_dir}/functions.lib.rb"

$whois_db_client=PG::Connection.new(:host => $whois_db_host, :dbname => $whois_db, :user => $whois_db_user, :password => $whois_db_pass)
$inetnums=[]
i_geocity_client

class IPAddr
  def cidr_mask
    case (@family)
    when Socket::AF_INET
      32 - Math.log2((1<<32) - @mask_addr).to_i
    else
      raise AddressFamilyError, "unsupported address family"
    end
  end
end

def get_db(url,rr_name,db_filename)
	if ! File.exists?(db_filename)
		$err_logger.debug "File for #{rr_name} doesn't exists, downloadling from #{url}"
		if url.end_with?('.gz')
			req="curl #{url} -o #{db_filename}.gz;gzip -df #{db_filename}.gz"
		else
			req="curl #{url} -o #{db_filename}"
		end
		res=system(req)
		return res
	else
		$err_logger.debug "File for #{rr_name} exists, it is #{db_filename}"
		res=true
		return res
	end
end

def parse_db(db_filename)
	$err_logger.info "Started parsing #{db_filename}"
	inetnums=[]
	begin
		data_raw=File.read(db_filename).encode('utf-8', :invalid => :replace, :undef => :replace)
	rescue => e
		puts e.to_s
	end
	data_raw.split("\n\n").each do |raw_object|
		if raw_object.start_with?("route:")
			$err_logger.debug "Found route object"
			begin
				raw_ip=raw_object.match(/^route:.*$/).to_s.gsub(/^route:[\ \t]*/,"").delete(" ")
				raw_asn=raw_object.match(/^origin:.*$/).to_s.gsub(/^origin:[\ \t]*(AS|as|As|aS)/,"").delete(" ").to_i
			rescue => e
				$err_logger.error 'error while converting object data'
				$err_logger.error raw_object
				$err_logger.error e.to_s
				raw_ip=nil
				raw_asn=nil
			end
			line={}
			ip=nil
			begin
				ip=IPAddr.new(raw_ip)
			rescue => e
				$err_logger.error "Cannot cast an IP net:"
				$err_logger.error e.to_s
				$err_logger.error raw_ip.inspect
			end
			$err_logger.debug "Found ASN: #{raw_asn}"
			$err_logger.debug "Found IP: #{raw_ip}"
			line["asn"]=raw_asn.to_i
			line_ip=ip.to_s
			line_mask=ip.cidr_mask
			line["network"]="#{line_ip}/#{line_mask}"
			line.merge!(get_geo_info(line_ip))
			if line["asn"] and line["network"]
				$err_logger.debug "Got full info, adding:"
				$err_logger.debug line.inspect
				inetnums.push(line)
			else
				$err_logger.error "Cannot get full data for:"
				$err_logger.error raw_object
				$err_logger.error line.inspect
			end
		end
	end
	$err_logger.info "Finished parsing, got #{inetnums.length} correct route entries"
	return inetnums
end

$rr_urls.each do |rr_url|
	rr_name=rr_url.gsub("ftp://ftp.","").gsub(/\.net.*/,"")
	$err_logger.info "Registry #{rr_name}"
	db_filename="#{Dir.pwd}/data/#{rr_name}.db"
	if get_db(rr_url,rr_name,db_filename)==true
		$err_logger.debug "DB downloaded, now parsing"
		new_num=parse_db(db_filename)
		$err_logger.debug "Parse finished, now merging"
		$inetnums=$inetnums | new_num
		$err_logger.debug "Merge finished"
	else
		$err_logger.error 'Cannot download DB for #{rr_name}'
	end
end

$err_logger.info "Finished with all the DB's, got #{$inetnums.length} route enties, inserting to SQL"
$whois_db_client.prepare('add_network_data', "insert into #{$whois_db_inetnums_table} (network,asn,country,region,city) values ($4,$1,$3,$5,$2) ON CONFLICT DO NOTHING;")
$inetnums.each do |inetnum|
	begin
		data_set=inetnum.sort.to_h.values
		res=$whois_db_client.exec_prepared('add_network_data',data_set)
	rescue => e
		$err_logger.error e.to_s
		$err_logger.error data_set
	end
end

$err_logger.info "SQL insert finished"
