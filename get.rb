require "#{Dir.pwd}/functions.lib.rb"

if ARGV[0]
	puts get_info(ARGV[0]).to_s
else
	puts 'Need an IP'
end
