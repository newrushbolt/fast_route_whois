# fast_route_whois

You need to require #{fast_route_whois_dir}/function.lib.rb and call get_info("91.230.60.11").
In return you'll get a hash with data like that: {"network"=>"91.230.60.0", "netmask"=>"255.255.254.0", "asn"=>59627} or nil.
you also need $err_logger object defined in your app
