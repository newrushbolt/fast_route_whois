require 'etc'
require 'geoip'
require 'mysql2'
#require 'ruby-prof'
require 'whois'

$get_dir=File.expand_path(File.dirname(__FILE__))
require "#{$get_dir}/functions.lib.rb"
$err_logger=Logger.new("#{$get_dir}/#{$log_dir}/get.log")
$err_logger.level=$log_level
if ARGV[1]
    case ARGV[1]
    when debug
	$err_logger.level=Logger::DEBUG
    when info
	$err_logger.level=Logger::IFNO
    when warn
	$err_logger.level=Logger::WARN
    when error
	$err_logger.level=Logger::ERROR
    when fatal
	$err_logger.level=Logger::FATAL
    end
end

if ARGV[0]
	puts get_info(ARGV[0]).to_s
else
	puts 'Need an IP'
end
