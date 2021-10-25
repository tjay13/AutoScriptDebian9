-- MySQL dump 10.16  Distrib 10.1.48-MariaDB, for debian-linux-gnu (x86_64)
--
-- Host: localhost    Database: tsholo_vpn1
-- ------------------------------------------------------
-- Server version	10.1.48-MariaDB-0+deb9u2

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `anti_ddos`
--

DROP TABLE IF EXISTS `anti_ddos`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `anti_ddos` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `attempts` int(11) NOT NULL DEFAULT '0',
  `ip` varchar(128) NOT NULL DEFAULT '0.0.0.0',
  `timestamp` int(11) NOT NULL,
  `logs_date` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM AUTO_INCREMENT=107 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `anti_ddos`
--

LOCK TABLES `anti_ddos` WRITE;
/*!40000 ALTER TABLE `anti_ddos` DISABLE KEYS */;
INSERT INTO `anti_ddos` VALUES (106,1,'60.217.75.69',1630628125,'2021-09-03 06:00:25');
/*!40000 ALTER TABLE `anti_ddos` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `attention`
--

DROP TABLE IF EXISTS `attention`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `attention` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `attention_msg` text NOT NULL,
  `attention_date` datetime NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM AUTO_INCREMENT=2 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `attention`
--

LOCK TABLES `attention` WRITE;
/*!40000 ALTER TABLE `attention` DISABLE KEYS */;
/*!40000 ALTER TABLE `attention` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `bandwidth_logs`
--

DROP TABLE IF EXISTS `bandwidth_logs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `bandwidth_logs` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `server` text NOT NULL,
  `server_ip` text NOT NULL,
  `server_port` text NOT NULL,
  `since_connected` text NOT NULL,
  `username` text NOT NULL,
  `ipaddress` text NOT NULL,
  `bytes_received` text NOT NULL,
  `bytes_sent` text NOT NULL,
  `bandwidth` bigint(50) NOT NULL DEFAULT '0',
  `time_in` datetime NOT NULL,
  `time_out` datetime NOT NULL,
  `status` enum('offline','online') NOT NULL,
  `timestamp` int(11) NOT NULL,
  `category` enum('premium','vip','ph','private','free') NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `bandwidth_logs`
--

LOCK TABLES `bandwidth_logs` WRITE;
/*!40000 ALTER TABLE `bandwidth_logs` DISABLE KEYS */;
/*!40000 ALTER TABLE `bandwidth_logs` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `bandwith_logs`
--

DROP TABLE IF EXISTS `bandwith_logs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `bandwith_logs` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `server` text NOT NULL,
  `username` text NOT NULL,
  `bytes_received` text NOT NULL,
  `bytes_sent` text NOT NULL,
  `bandwith` bigint(50) NOT NULL DEFAULT '0',
  `time_in` datetime NOT NULL,
  `time_out` datetime NOT NULL,
  `status` enum('offline','online') NOT NULL,
  `timestamp` int(11) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `bandwith_logs`
--

LOCK TABLES `bandwith_logs` WRITE;
/*!40000 ALTER TABLE `bandwith_logs` DISABLE KEYS */;
/*!40000 ALTER TABLE `bandwith_logs` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `conversion_logs`
--

DROP TABLE IF EXISTS `conversion_logs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `conversion_logs` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `client_id` int(11) NOT NULL,
  `premium` varchar(755) NOT NULL,
  `vip` varchar(755) NOT NULL,
  `description` varchar(755) NOT NULL,
  `logs_date` datetime NOT NULL,
  `ipaddress` varchar(32) NOT NULL DEFAULT '0.0.0.0',
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `conversion_logs`
--

LOCK TABLES `conversion_logs` WRITE;
/*!40000 ALTER TABLE `conversion_logs` DISABLE KEYS */;
/*!40000 ALTER TABLE `conversion_logs` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `credits_logs`
--

DROP TABLE IF EXISTS `credits_logs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `credits_logs` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `credits_id` varchar(11) COLLATE utf8_unicode_ci NOT NULL,
  `credits_id2` int(11) NOT NULL,
  `credits_username` varchar(50) COLLATE utf8_unicode_ci NOT NULL,
  `credits_qty` int(11) NOT NULL,
  `credits_date` datetime NOT NULL,
  `ipaddress` varchar(15) COLLATE utf8_unicode_ci NOT NULL DEFAULT '0.0.0.0',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `credits_logs`
--

LOCK TABLES `credits_logs` WRITE;
/*!40000 ALTER TABLE `credits_logs` DISABLE KEYS */;
/*!40000 ALTER TABLE `credits_logs` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `cronjob_banned_ip`
--

DROP TABLE IF EXISTS `cronjob_banned_ip`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `cronjob_banned_ip` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `attempts` int(11) NOT NULL DEFAULT '0',
  `content` varchar(128) NOT NULL DEFAULT 'Attempting',
  `ip` varchar(128) NOT NULL DEFAULT '0.0.0.0',
  `logs_date` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM AUTO_INCREMENT=3 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `cronjob_banned_ip`
--

LOCK TABLES `cronjob_banned_ip` WRITE;
/*!40000 ALTER TABLE `cronjob_banned_ip` DISABLE KEYS */;
/*!40000 ALTER TABLE `cronjob_banned_ip` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `cronjob_logs`
--

DROP TABLE IF EXISTS `cronjob_logs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `cronjob_logs` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `content` text NOT NULL,
  `ipaddress` varchar(128) NOT NULL DEFAULT '0.0.0.0',
  `timestamp` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM AUTO_INCREMENT=3474 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `cronjob_logs`
--

LOCK TABLES `cronjob_logs` WRITE;
/*!40000 ALTER TABLE `cronjob_logs` DISABLE KEYS */;
/*!40000 ALTER TABLE `cronjob_logs` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `download`
--

DROP TABLE IF EXISTS `download`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `download` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `download_category` enum('public','seller') NOT NULL,
  `download_title` varchar(767) NOT NULL,
  `download_msg` text NOT NULL,
  `download_network` enum('GTM','SMART','TNT','SUN','ALLINONE') NOT NULL,
  `download_device` enum('ANDROID','IOS','WINDOWS','CONFIG') NOT NULL,
  `download_file` varchar(999) NOT NULL,
  `download_date` datetime NOT NULL,
  `views` int(11) NOT NULL DEFAULT '0',
  `downloaded` int(11) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`)
) ENGINE=MyISAM AUTO_INCREMENT=2 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `download`
--

LOCK TABLES `download` WRITE;
/*!40000 ALTER TABLE `download` DISABLE KEYS */;
/*!40000 ALTER TABLE `download` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `duration`
--

DROP TABLE IF EXISTS `duration`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `duration` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `duration_name` varchar(255) COLLATE utf8_unicode_ci NOT NULL,
  `duration_time` bigint(50) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=37 DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `duration`
--

LOCK TABLES `duration` WRITE;
/*!40000 ALTER TABLE `duration` DISABLE KEYS */;
INSERT INTO `duration` VALUES (1,'1 Hour',3600),(2,'2 Hours',7200),(3,'3 Hours',10800),(4,'4 Hours',14400),(5,'5 Hours',18000),(6,'6 Hours',21600),(7,'7 Hours',25200),(8,'8 Hours',28800),(9,'9 Hours',32400),(10,'10 Hours',36000),(11,'11 Hours',39600),(12,'12 Hours',43200),(13,'13 Hours',46800),(14,'14 Hours',50400),(15,'15 Hours',54000),(16,'16 Hours',57600),(17,'17 Hours',61200),(18,'18 Hours',64800),(19,'19 Hours',68400),(20,'20 Hours',72000),(21,'21 Hours',75600),(22,'22 Hours',79200),(23,'23 Hours',82800),(24,'1 Day',86400),(25,'2 Days',172800),(26,'3 Days',259200),(27,'4 Days',345600),(28,'5 Days',432000),(29,'6 Days',518400),(30,'7 Days',604800),(31,'8 Days',691200),(32,'9 Days',777600),(33,'10 Days',864000),(34,'15 Days',1296000),(35,'20 Days',1728000),(36,'30 Days',2592000);
/*!40000 ALTER TABLE `duration` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `duration_logs`
--

DROP TABLE IF EXISTS `duration_logs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `duration_logs` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `duration_id` int(11) NOT NULL,
  `duration_id2` int(11) NOT NULL,
  `duration_username` varchar(50) COLLATE utf8_unicode_ci NOT NULL,
  `duration_qty` int(11) NOT NULL,
  `duration_item` varchar(50) COLLATE utf8_unicode_ci NOT NULL,
  `duration_date` datetime NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `duration_logs`
--

LOCK TABLES `duration_logs` WRITE;
/*!40000 ALTER TABLE `duration_logs` DISABLE KEYS */;
/*!40000 ALTER TABLE `duration_logs` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `freeze_request`
--

DROP TABLE IF EXISTS `freeze_request`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `freeze_request` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `content` varchar(128) NOT NULL DEFAULT 'Freeze Request',
  `status` enum('pending','approved') NOT NULL DEFAULT 'pending',
  `client_id` int(11) NOT NULL,
  `client_name` varchar(128) NOT NULL,
  `client_ipaddress` varchar(128) NOT NULL DEFAULT '0.0.0.0',
  `request_date` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `reseller_id` int(11) NOT NULL,
  `reseller_name` varchar(128) NOT NULL,
  `reseller_ipaddress` varchar(128) NOT NULL DEFAULT '0.0.0.0',
  `process_date` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `freeze_request`
--

LOCK TABLES `freeze_request` WRITE;
/*!40000 ALTER TABLE `freeze_request` DISABLE KEYS */;
/*!40000 ALTER TABLE `freeze_request` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `limit_logs`
--

DROP TABLE IF EXISTS `limit_logs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `limit_logs` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `id_user` int(11) NOT NULL,
  `client_id` int(11) NOT NULL,
  `username` varchar(64) NOT NULL,
  `subadmin_limit` int(11) NOT NULL DEFAULT '0',
  `reseller_limit` int(11) NOT NULL DEFAULT '0',
  `subreseller_limit` int(11) NOT NULL DEFAULT '0',
  `client_limit` int(11) NOT NULL,
  `user_level` enum('normal','reseller','subreseller','subadmin','admin','superadmin') NOT NULL DEFAULT 'normal',
  `logs_date` datetime NOT NULL,
  `ipaddress` varchar(64) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `limit_logs`
--

LOCK TABLES `limit_logs` WRITE;
/*!40000 ALTER TABLE `limit_logs` DISABLE KEYS */;
/*!40000 ALTER TABLE `limit_logs` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `limit_registration`
--

DROP TABLE IF EXISTS `limit_registration`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `limit_registration` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `ipaddress` varchar(20) COLLATE utf8_unicode_ci NOT NULL,
  `regtime` int(11) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=6 DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `limit_registration`
--

LOCK TABLES `limit_registration` WRITE;
/*!40000 ALTER TABLE `limit_registration` DISABLE KEYS */;
/*!40000 ALTER TABLE `limit_registration` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `log`
--

DROP TABLE IF EXISTS `log`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `log` (
  `log_id` int(10) unsigned NOT NULL,
  `user_id` varchar(32) COLLATE utf8_unicode_ci NOT NULL,
  `user_online` tinyint(1) NOT NULL DEFAULT '0',
  `user_ip` varchar(255) COLLATE utf8_unicode_ci NOT NULL,
  `untrusted_ip` varchar(255) COLLATE utf8_unicode_ci DEFAULT NULL,
  `log_server` varchar(255) COLLATE utf8_unicode_ci NOT NULL,
  `log_server_ip` varchar(255) COLLATE utf8_unicode_ci NOT NULL,
  `log_trusted_ip` varchar(32) COLLATE utf8_unicode_ci DEFAULT NULL,
  `log_trusted_port` varchar(16) COLLATE utf8_unicode_ci DEFAULT NULL,
  `log_remote_ip` varchar(32) COLLATE utf8_unicode_ci DEFAULT NULL,
  `log_remote_port` varchar(16) COLLATE utf8_unicode_ci DEFAULT NULL,
  `log_start_time` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `log_end_time` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `log_received` bigint(20) NOT NULL DEFAULT '0',
  `log_send` bigint(20) NOT NULL DEFAULT '0',
  `user_enable` tinyint(1) NOT NULL DEFAULT '1',
  `user_start_date` date NOT NULL,
  `user_end_date` date NOT NULL,
  `user_last_server` varchar(255) COLLATE utf8_unicode_ci NOT NULL,
  PRIMARY KEY (`log_id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `log`
--

LOCK TABLES `log` WRITE;
/*!40000 ALTER TABLE `log` DISABLE KEYS */;
/*!40000 ALTER TABLE `log` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `login_attempts`
--

DROP TABLE IF EXISTS `login_attempts`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `login_attempts` (
  `ip` varchar(20) DEFAULT NULL,
  `attempts` int(11) DEFAULT '0',
  `lastlogin` datetime DEFAULT NULL,
  `timestamp` int(11) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `login_attempts`
--

LOCK TABLES `login_attempts` WRITE;
/*!40000 ALTER TABLE `login_attempts` DISABLE KEYS */;
/*!40000 ALTER TABLE `login_attempts` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `login_attempts_logs`
--

DROP TABLE IF EXISTS `login_attempts_logs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `login_attempts_logs` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `ip` varchar(20) DEFAULT NULL,
  `user_name` varchar(64) NOT NULL,
  `logs_date` datetime NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM AUTO_INCREMENT=10 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `login_attempts_logs`
--

LOCK TABLES `login_attempts_logs` WRITE;
/*!40000 ALTER TABLE `login_attempts_logs` DISABLE KEYS */;
/*!40000 ALTER TABLE `login_attempts_logs` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `login_banned_ip`
--

DROP TABLE IF EXISTS `login_banned_ip`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `login_banned_ip` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `attempts` int(11) NOT NULL DEFAULT '0',
  `ip` varchar(128) NOT NULL DEFAULT '0.0.0.0',
  `logs_date` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM AUTO_INCREMENT=6 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `login_banned_ip`
--

LOCK TABLES `login_banned_ip` WRITE;
/*!40000 ALTER TABLE `login_banned_ip` DISABLE KEYS */;
/*!40000 ALTER TABLE `login_banned_ip` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `openvpn`
--

DROP TABLE IF EXISTS `openvpn`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `openvpn` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `server_name` text NOT NULL,
  `CommonName` text NOT NULL,
  `RealAddress` text NOT NULL,
  `BytesReceived` text NOT NULL,
  `BytesSent` text NOT NULL,
  `Since` text NOT NULL,
  `VirtualAddress` text NOT NULL,
  `LastRef` text NOT NULL,
  `updated` bigint(20) NOT NULL,
  `logs_date` datetime NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `openvpn`
--

LOCK TABLES `openvpn` WRITE;
/*!40000 ALTER TABLE `openvpn` DISABLE KEYS */;
/*!40000 ALTER TABLE `openvpn` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `payments`
--

DROP TABLE IF EXISTS `payments`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `payments` (
  `payment_id` int(11) NOT NULL AUTO_INCREMENT,
  `item_number` varchar(255) COLLATE utf8_unicode_ci NOT NULL,
  `txn_id` varchar(255) COLLATE utf8_unicode_ci NOT NULL,
  `payment_gross` float(10,2) NOT NULL,
  `currency_code` varchar(5) COLLATE utf8_unicode_ci NOT NULL,
  `payment_status` varchar(255) COLLATE utf8_unicode_ci NOT NULL,
  `payment_date` datetime NOT NULL,
  PRIMARY KEY (`payment_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `payments`
--

LOCK TABLES `payments` WRITE;
/*!40000 ALTER TABLE `payments` DISABLE KEYS */;
/*!40000 ALTER TABLE `payments` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `pricing`
--

DROP TABLE IF EXISTS `pricing`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `pricing` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `pricing_code` varchar(64) NOT NULL DEFAULT '',
  `pricing_level` enum('subadmin','reseller','subreseller') NOT NULL,
  `pricing_qty` int(11) NOT NULL DEFAULT '0',
  `pricing_amount` float(10,2) NOT NULL,
  `pricing_currency` enum('PHP','USD') NOT NULL,
  `pricing_type` enum('Vouchers','Reseller Slot','Sub Reseller Slot','Client Slot') NOT NULL,
  `pricing_date` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `pricing`
--

LOCK TABLES `pricing` WRITE;
/*!40000 ALTER TABLE `pricing` DISABLE KEYS */;
/*!40000 ALTER TABLE `pricing` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `product`
--

DROP TABLE IF EXISTS `product`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `product` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `product_name` varchar(255) NOT NULL,
  `product_price` float(10,2) NOT NULL,
  `product_currency` varchar(255) NOT NULL,
  `product_items` int(11) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `product`
--

LOCK TABLES `product` WRITE;
/*!40000 ALTER TABLE `product` DISABLE KEYS */;
/*!40000 ALTER TABLE `product` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `recovery_logs`
--

DROP TABLE IF EXISTS `recovery_logs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `recovery_logs` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `recovery_menu` varchar(255) NOT NULL,
  `recovery_ipaddress` varchar(15) NOT NULL DEFAULT '0.0.0.0',
  `recovery_date` datetime NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `recovery_logs`
--

LOCK TABLES `recovery_logs` WRITE;
/*!40000 ALTER TABLE `recovery_logs` DISABLE KEYS */;
/*!40000 ALTER TABLE `recovery_logs` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `reloadduration_logs`
--

DROP TABLE IF EXISTS `reloadduration_logs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `reloadduration_logs` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `duration_id` int(11) NOT NULL,
  `duration_id2` int(11) NOT NULL,
  `duration_username` varchar(50) COLLATE utf8_unicode_ci NOT NULL,
  `duration_item` varchar(50) COLLATE utf8_unicode_ci NOT NULL,
  `duration_date` datetime NOT NULL,
  `duration_type` enum('premium','vip','private') COLLATE utf8_unicode_ci NOT NULL DEFAULT 'premium',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `reloadduration_logs`
--

LOCK TABLES `reloadduration_logs` WRITE;
/*!40000 ALTER TABLE `reloadduration_logs` DISABLE KEYS */;
/*!40000 ALTER TABLE `reloadduration_logs` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `server_list`
--

DROP TABLE IF EXISTS `server_list`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `server_list` (
  `server_id` int(255) NOT NULL AUTO_INCREMENT,
  `server_name` varchar(255) NOT NULL,
  `server_ip` varchar(20) NOT NULL,
  `server_connected` int(11) NOT NULL DEFAULT '0',
  `server_category` enum('premium','vip','free','private') NOT NULL DEFAULT 'premium',
  `server_port` int(11) NOT NULL DEFAULT '80',
  `server_folder` varchar(255) NOT NULL,
  `server_tcp` varchar(15) NOT NULL DEFAULT 'tcp1',
  `server_parser` varchar(255) NOT NULL,
  `status` int(10) NOT NULL,
  PRIMARY KEY (`server_id`)
) ENGINE=MyISAM AUTO_INCREMENT=2 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `server_list`
--

LOCK TABLES `server_list` WRITE;
/*!40000 ALTER TABLE `server_list` DISABLE KEYS */;
/*!40000 ALTER TABLE `server_list` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `support_message`
--

DROP TABLE IF EXISTS `support_message`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `support_message` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `ticket_id` int(11) NOT NULL,
  `support_message` text NOT NULL,
  `support_user_id` int(11) NOT NULL,
  `support_name` varchar(767) NOT NULL,
  `support_groupname` varchar(767) NOT NULL,
  `support_date` datetime NOT NULL,
  `support_ipaddress` varchar(15) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `support_message`
--

LOCK TABLES `support_message` WRITE;
/*!40000 ALTER TABLE `support_message` DISABLE KEYS */;
/*!40000 ALTER TABLE `support_message` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `support_ticket`
--

DROP TABLE IF EXISTS `support_ticket`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `support_ticket` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `ticket_name` varchar(767) NOT NULL,
  `ticket_subject` varchar(767) NOT NULL,
  `ticket_message` text NOT NULL,
  `ticket_status` enum('open','customer-reply','answered','closed') NOT NULL,
  `ticket_date` datetime NOT NULL,
  `ticket_update` datetime NOT NULL,
  `ip_address` varchar(767) NOT NULL,
  `ticket_id_user` int(11) NOT NULL,
  `ticket_groupname` varchar(767) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `support_ticket`
--

LOCK TABLES `support_ticket` WRITE;
/*!40000 ALTER TABLE `support_ticket` DISABLE KEYS */;
/*!40000 ALTER TABLE `support_ticket` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `suspension_logs`
--

DROP TABLE IF EXISTS `suspension_logs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `suspension_logs` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `is_suspended` int(11) NOT NULL,
  `client_id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `offense` varchar(225) NOT NULL,
  `logs_date` datetime NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `suspension_logs`
--

LOCK TABLES `suspension_logs` WRITE;
/*!40000 ALTER TABLE `suspension_logs` DISABLE KEYS */;
/*!40000 ALTER TABLE `suspension_logs` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `suspension_recovery_logs`
--

DROP TABLE IF EXISTS `suspension_recovery_logs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `suspension_recovery_logs` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `client_id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `suspend_date` datetime NOT NULL,
  `offense` varchar(225) NOT NULL,
  `logs_date` datetime NOT NULL,
  `is_unsuspended` int(11) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `suspension_recovery_logs`
--

LOCK TABLES `suspension_recovery_logs` WRITE;
/*!40000 ALTER TABLE `suspension_recovery_logs` DISABLE KEYS */;
/*!40000 ALTER TABLE `suspension_recovery_logs` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `user`
--

DROP TABLE IF EXISTS `user`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `user` (
  `id_user` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(128) NOT NULL,
  `email` varchar(64) NOT NULL,
  `username` varchar(64) NOT NULL,
  `password` varchar(755) NOT NULL,
  `auth_vpn` varchar(512) NOT NULL,
  `confirmcode` varchar(32) NOT NULL,
  `last_loggedin` datetime NOT NULL,
  `user_level` enum('normal','reseller','subreseller','subadmin','superadmin') NOT NULL DEFAULT 'normal',
  `forgot` datetime NOT NULL,
  `status` enum('live','suspended','banned','freeze') NOT NULL,
  `private_duration` bigint(50) NOT NULL DEFAULT '0',
  `vip_duration` bigint(50) NOT NULL DEFAULT '0',
  `is_vip` tinyint(1) NOT NULL DEFAULT '0',
  `is_duration` bigint(50) DEFAULT '0',
  `is_credits` int(11) NOT NULL,
  `is_offense` int(1) NOT NULL,
  `is_freeze` int(1) NOT NULL DEFAULT '1',
  `is_ban` int(1) NOT NULL DEFAULT '1',
  `is_active` int(1) NOT NULL,
  `is_suspend` int(1) NOT NULL DEFAULT '1',
  `is_groupname` varchar(64) NOT NULL,
  `suspend_date` datetime NOT NULL,
  `upline` int(11) NOT NULL DEFAULT '1',
  `regdate` datetime NOT NULL,
  `timestamp` bigint(64) NOT NULL DEFAULT '0',
  `ip_address` varchar(15) NOT NULL,
  `web_browser` varchar(767) NOT NULL,
  `last_active_time` datetime NOT NULL,
  `login_timestamp` int(11) NOT NULL DEFAULT '0',
  `login_status` enum('offline','online') NOT NULL,
  `is_connected` int(11) NOT NULL DEFAULT '0',
  `bandwidth_premium` bigint(128) NOT NULL DEFAULT '0',
  `bandwidth_vip` bigint(128) NOT NULL DEFAULT '0',
  `bandwidth_free` bigint(128) NOT NULL DEFAULT '0',
  `bandwidth_ph` bigint(128) NOT NULL DEFAULT '0',
  `bandwidth_private` bigint(128) NOT NULL DEFAULT '0',
  `vip_control` tinyint(1) NOT NULL DEFAULT '0',
  `private_control` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id_user`)
) ENGINE=MyISAM AUTO_INCREMENT=106 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `user`
--

LOCK TABLES `user` WRITE;
/*!40000 ALTER TABLE `user` DISABLE KEYS */;
INSERT INTO `user` VALUES (1,'Deekay VPN','joashsingh14@gmail.com','Deekay','jpqeysq7ftKtzZrUsZuXnMKJoYbXp8XDy4rHx5y5m6Q=','a80aa828124f4837ba30df1a3b713110','y','2021-09-03 07:46:16','superadmin','2019-10-27 16:34:47','live',7200,7200,1,7200,1,0,0,0,1,0,'','0000-00-00 00:00:00',1,'2017-10-31 16:15:43',0,'20.87.25.209','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36','2021-09-03 07:46:16',0,'online',0,0,0,0,0,0,1,1);
/*!40000 ALTER TABLE `user` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `user_online`
--

DROP TABLE IF EXISTS `user_online`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `user_online` (
  `user_id` varchar(32) COLLATE utf8_unicode_ci NOT NULL,
  `user_pass` varchar(32) COLLATE utf8_unicode_ci NOT NULL DEFAULT '1234',
  `user_mail` varchar(64) COLLATE utf8_unicode_ci DEFAULT NULL,
  `user_phone` varchar(16) COLLATE utf8_unicode_ci DEFAULT NULL,
  `user_online` tinyint(1) NOT NULL DEFAULT '0',
  `user_enable` tinyint(1) NOT NULL DEFAULT '1',
  `user_start_date` date NOT NULL,
  `user_end_date` date NOT NULL,
  `user_serial` varchar(255) COLLATE utf8_unicode_ci DEFAULT NULL,
  `user_data` bigint(20) NOT NULL DEFAULT '0',
  `user_limit` bigint(20) NOT NULL DEFAULT '42949672960',
  `user_last_server` varchar(255) COLLATE utf8_unicode_ci NOT NULL,
  `user_ip` varchar(255) COLLATE utf8_unicode_ci DEFAULT NULL,
  `user_vpn` varchar(255) COLLATE utf8_unicode_ci NOT NULL,
  `user_port` varchar(255) COLLATE utf8_unicode_ci NOT NULL,
  `user_live` bigint(20) NOT NULL DEFAULT '0',
  `user_token` varchar(255) COLLATE utf8_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`user_id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `user_online`
--

LOCK TABLES `user_online` WRITE;
/*!40000 ALTER TABLE `user_online` DISABLE KEYS */;
/*!40000 ALTER TABLE `user_online` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `user_profile`
--

DROP TABLE IF EXISTS `user_profile`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `user_profile` (
  `id` int(5) NOT NULL AUTO_INCREMENT,
  `profile_id` int(5) NOT NULL,
  `profile_image` varchar(767) NOT NULL,
  `profile_address` varchar(255) NOT NULL,
  `profile_number` varchar(13) NOT NULL,
  `profile_fb` text NOT NULL,
  `bdo` int(1) NOT NULL DEFAULT '0',
  `bitcoin` int(1) NOT NULL DEFAULT '0',
  `bpi` int(1) NOT NULL DEFAULT '0',
  `cebuana` int(1) NOT NULL DEFAULT '0',
  `gcash` int(1) NOT NULL DEFAULT '0',
  `lbc` int(1) NOT NULL DEFAULT '0',
  `meetup` int(1) NOT NULL DEFAULT '0',
  `mlkwartapadala` int(1) NOT NULL DEFAULT '0',
  `palawanexpress` int(1) NOT NULL DEFAULT '0',
  `paypal` int(1) NOT NULL DEFAULT '0',
  `prepaidload` int(1) NOT NULL DEFAULT '0',
  `rcbc` int(1) NOT NULL DEFAULT '0',
  `rdperapadala` int(1) NOT NULL DEFAULT '0',
  `smartmoney` int(1) NOT NULL DEFAULT '0',
  `unionbank` int(1) NOT NULL DEFAULT '0',
  `westernunion` int(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`)
) ENGINE=MyISAM AUTO_INCREMENT=106 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `user_profile`
--

LOCK TABLES `user_profile` WRITE;
/*!40000 ALTER TABLE `user_profile` DISABLE KEYS */;
INSERT INTO `user_profile` VALUES (1,1,'1572274453.png',' South Africa, Durban','0846885813','',0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0);
/*!40000 ALTER TABLE `user_profile` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `username_logs`
--

DROP TABLE IF EXISTS `username_logs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `username_logs` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `old_username` varchar(50) NOT NULL,
  `new_username` varchar(50) NOT NULL,
  `old_level` varchar(64) NOT NULL,
  `new_level` varchar(64) NOT NULL,
  `old_upline` int(11) NOT NULL,
  `new_upline` int(11) NOT NULL,
  `client_id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `logs_date` datetime NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `username_logs`
--

LOCK TABLES `username_logs` WRITE;
/*!40000 ALTER TABLE `username_logs` DISABLE KEYS */;
/*!40000 ALTER TABLE `username_logs` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `users_bandwith`
--

DROP TABLE IF EXISTS `users_bandwith`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `users_bandwith` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `username` varchar(64) NOT NULL,
  `bandwith` int(11) NOT NULL,
  `category` enum('free','ph','vip','premium') NOT NULL,
  `status` enum('offline','online') NOT NULL,
  `timestamp` int(11) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `users_bandwith`
--

LOCK TABLES `users_bandwith` WRITE;
/*!40000 ALTER TABLE `users_bandwith` DISABLE KEYS */;
/*!40000 ALTER TABLE `users_bandwith` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `users_delete`
--

DROP TABLE IF EXISTS `users_delete`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `users_delete` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `delete_timestamp` int(11) NOT NULL,
  `id_user` int(11) NOT NULL,
  `subadmin_limit` int(11) NOT NULL DEFAULT '0',
  `reseller_limit` int(11) NOT NULL DEFAULT '0',
  `subreseller_limit` int(11) NOT NULL DEFAULT '0',
  `client_limit` int(11) NOT NULL,
  `name` varchar(128) NOT NULL,
  `email` varchar(64) NOT NULL,
  `username` varchar(64) NOT NULL,
  `password` varchar(755) NOT NULL,
  `auth_vpn` varchar(512) NOT NULL,
  `confirmcode` varchar(32) NOT NULL,
  `last_loggedin` datetime NOT NULL,
  `user_level` enum('normal','reseller','subreseller','subadmin','superadmin') NOT NULL DEFAULT 'normal',
  `forgot` datetime NOT NULL,
  `status` enum('live','suspended','banned','freeze') NOT NULL,
  `vip_duration` bigint(50) NOT NULL DEFAULT '0',
  `is_vip` tinyint(1) NOT NULL DEFAULT '0',
  `is_duration` bigint(50) NOT NULL,
  `is_credits` int(11) NOT NULL,
  `is_offense` int(1) NOT NULL,
  `is_freeze` int(1) NOT NULL DEFAULT '1',
  `is_ban` int(1) NOT NULL DEFAULT '1',
  `is_active` int(1) NOT NULL,
  `is_suspend` int(1) NOT NULL DEFAULT '1',
  `is_groupname` varchar(64) NOT NULL,
  `suspend_date` datetime NOT NULL,
  `upline` int(11) NOT NULL DEFAULT '1',
  `regdate` datetime NOT NULL,
  `timestamp` bigint(64) NOT NULL DEFAULT '0',
  `ip_address` varchar(15) NOT NULL,
  `web_browser` varchar(767) NOT NULL,
  `last_active_time` datetime NOT NULL,
  `login_timestamp` int(11) NOT NULL DEFAULT '0',
  `login_status` enum('offline','online') NOT NULL,
  `bandwith` bigint(128) NOT NULL DEFAULT '0',
  `is_connected` int(11) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `users_delete`
--

LOCK TABLES `users_delete` WRITE;
/*!40000 ALTER TABLE `users_delete` DISABLE KEYS */;
/*!40000 ALTER TABLE `users_delete` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `users_payment`
--

DROP TABLE IF EXISTS `users_payment`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `users_payment` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) NOT NULL,
  `payments_id` int(11) NOT NULL,
  `payment_amount` float(10,2) NOT NULL,
  `payment_currency` varchar(255) NOT NULL,
  `payment_date` datetime NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `users_payment`
--

LOCK TABLES `users_payment` WRITE;
/*!40000 ALTER TABLE `users_payment` DISABLE KEYS */;
/*!40000 ALTER TABLE `users_payment` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `voucher_logs`
--

DROP TABLE IF EXISTS `voucher_logs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `voucher_logs` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `code_name` varchar(50) NOT NULL,
  `user_id` int(100) NOT NULL,
  `client_name` varchar(755) NOT NULL,
  `reseller_id` int(100) NOT NULL,
  `reseller_name` varchar(64) NOT NULL,
  `is_qty` int(11) NOT NULL DEFAULT '1',
  `is_used` int(1) NOT NULL,
  `date_used` datetime NOT NULL,
  `is_date` date NOT NULL,
  `category` enum('premium','vip') NOT NULL DEFAULT 'premium',
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `voucher_logs`
--

LOCK TABLES `voucher_logs` WRITE;
/*!40000 ALTER TABLE `voucher_logs` DISABLE KEYS */;
/*!40000 ALTER TABLE `voucher_logs` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `vouchers`
--

DROP TABLE IF EXISTS `vouchers`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `vouchers` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `code_name` varchar(50) NOT NULL,
  `user_id` int(100) NOT NULL,
  `client_name` varchar(755) NOT NULL,
  `reseller_id` int(100) NOT NULL,
  `reseller_name` varchar(64) NOT NULL,
  `is_qty` int(11) NOT NULL DEFAULT '1',
  `is_used` int(1) NOT NULL,
  `duration` bigint(50) NOT NULL DEFAULT '0',
  `gen_date` datetime NOT NULL,
  `date_used` datetime NOT NULL,
  `category` enum('premium','vip') NOT NULL DEFAULT 'premium',
  `permission` tinyint(1) NOT NULL DEFAULT '0',
  `ipaddress` varchar(20) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `vouchers`
--

LOCK TABLES `vouchers` WRITE;
/*!40000 ALTER TABLE `vouchers` DISABLE KEYS */;
/*!40000 ALTER TABLE `vouchers` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `vpn`
--

DROP TABLE IF EXISTS `vpn`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `vpn` (
  `user_id` varchar(32) COLLATE utf8_unicode_ci NOT NULL,
  `user_enable` tinyint(1) NOT NULL DEFAULT '1',
  `user_start_date` date NOT NULL,
  `user_end_date` date NOT NULL,
  `user_last_server` varchar(255) COLLATE utf8_unicode_ci NOT NULL,
  `user_ip` varchar(255) COLLATE utf8_unicode_ci DEFAULT NULL,
  `user_online` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`user_id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `vpn`
--

LOCK TABLES `vpn` WRITE;
/*!40000 ALTER TABLE `vpn` DISABLE KEYS */;
/*!40000 ALTER TABLE `vpn` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Dumping events for database 'dopekid_vpn18'
--

--
-- Dumping routines for database 'dopekid_vpn18'
--
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2021-09-03  2:15:39
