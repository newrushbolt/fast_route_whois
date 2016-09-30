#!/bin/bash

mkdir -p var/log
mkdir -p var/run
mkdir data
mysql -uroot -p< init/whois.sql

