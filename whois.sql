CREATE DATABASE  IF NOT EXISTS `fast_whois`;
USE `fast_whois`;

DROP TABLE IF EXISTS `fast_inetnums`;
CREATE TABLE `fast_inetnums` (
  `network` int(10) unsigned NOT NULL,
  `netmask` int(10) unsigned NOT NULL,
  `asn` int(10) unsigned NOT NULL,
  PRIMARY KEY (`network`,`netmask`) USING BTREE,
  UNIQUE KEY `uniq_id` (`network`,`netmask`) USING BTREE,
  KEY `full` (`network`,`netmask`,`asn`) USING BTREE
) ENGINE=MEMORY DEFAULT CHARSET=utf8;

DROP TABLE IF EXISTS `inetnums`;
CREATE TABLE `inetnums` (
  `network` int(10) unsigned NOT NULL,
  `netmask` int(10) unsigned NOT NULL,
  `asn` int(10) unsigned NOT NULL,
  PRIMARY KEY (`network`,`netmask`),
  UNIQUE KEY `uniq_id` (`network`,`netmask`),
  KEY `full` (`network`,`netmask`,`asn`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

SET SQL_MODE = '';
GRANT USAGE ON *.* TO fast_whois;
 DROP USER fast_whois;
SET SQL_MODE='TRADITIONAL,ALLOW_INVALID_DATES';
CREATE USER 'fast_whois' IDENTIFIED BY 'wb5nv6d8';

GRANT ALL ON `fast_whois`.* TO 'fast_whois';
