require 'etc'
require 'geoip'
require 'mysql2'
require 'rubygems'
require 'whois'
require 'json'

$app_dir='/home/mihailov.s/fast_route_whois'
$log_dir='var/log'
$log_level=Logger::INFO

$whois_db='fast_whois'
$whois_db_host='localhost'
$whois_db_user='fast_whois'
$whois_db_pass='wb5nv6d8'
$whois_db_inetnums_table='inetnums'
$whois_db_fast_inetnums_table='fast_inetnums'

$rr_urls=['ftp://ftp.apnic.net/public/apnic/whois/apnic.db.route.gz',
'ftp://ftp.arin.net/pub/rr/arin.db',
'ftp://ftp.ripe.net/ripe/dbase/split/ripe.db.route.gz',
'ftp://ftp.afrinic.net/dbase/afrinic.db.gz']

$private_nets=["10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","127.0.0.0/8", "169.254.0.0/16","224.0.0.0/4","240.0.0.0/4"]
#May need it later
#$ripe_prefix_url='https://stat.ripe.net/data/announced-prefixes/data.json?'
#$ripe_as_con_url='https://stat.ripe.net/data/as-routing-consistency/data.json?'
