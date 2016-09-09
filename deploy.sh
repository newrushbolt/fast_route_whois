#!/bin/bash

#Debian block
#apt-get update

apt-get install curl gzip mysql-server mysql-client libmysqlclient-dev
command curl -sSL https://rvm.io/mpapis.asc | gpg --import -
curl -sSL https://get.rvm.io | bash -s stable

source /etc/profile.d/rvm.sh
rvm install ruby-2.2
rvm --default use 2.2

gem install rest-client mysql2 whois json geoip logger

###MySQL init
service mysql restart
mysql -uroot -pwb5nv6d8< whois.sql

