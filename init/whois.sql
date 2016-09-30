CREATE DATABASE IF NOT EXISTS fast_whois;
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

CREATE USER 'fast_whois'@'localhost' IDENTIFIED BY 'wb5nv6d8';
GRANT ALL ON `fast_whois`.* TO 'fast_whois';
GRANT USAGE ON `fast_whois`.* TO fast_whois;

DELIMITER ;;
CREATE DEFINER=`fast_whois`@`localhost` TRIGGER `fast_whois`.`inetnums_AFTER_INSERT` AFTER INSERT ON `inetnums` FOR EACH ROW
BEGIN
    insert ignore into `fast_whois`.`fast_inetnums` values (NEW.network,NEW.netmask,NEW.asn);
END;;
CREATE DEFINER=`fast_whois`@`localhost` TRIGGER `fast_whois`.`inetnums_BEFORE_DELETE` BEFORE DELETE ON `inetnums` FOR EACH ROW
BEGIN
        delete from `fast_whois`.`fast_inetnums` where network = OLD.network and netmask = OLD.netmask;
END;;
DELIMITER ;

