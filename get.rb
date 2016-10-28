require 'logger'

$get_dir=File.expand_path(File.dirname(__FILE__))
$err_logger=Logger.new("#{$get_dir}/var/log/get.log")
$err_logger.level=Logger::DEBUG

require "#{$get_dir}/lib/whois.lib.rb"

if ARGV[2]
    case ARGV[2]
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

fast_whois=Fast_whois.new
slow_whois=Slow_whois.new
mode=nil

if ! ARGV[1]
	mode="slow"
else
	mode=ARGV[1]
end



if ARGV[0]
	case mode
	when "fast"
		res=fast_whois.get_ip_route(ARGV[0])
	when "slow"
		res=slow_whois.get_ip_route(ARGV[0])
	end
	
	puts res
	puts res.class
else
	puts 'Need an IP'
end
