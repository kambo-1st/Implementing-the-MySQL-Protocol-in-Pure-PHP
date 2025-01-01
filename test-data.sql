SET NAMES utf8;
SET time_zone = '+00:00';
SET foreign_key_checks = 0;
SET sql_mode = 'NO_AUTO_VALUE_ON_ZERO';

SET NAMES utf8mb4;

DROP DATABASE IF EXISTS `exampledb`;

CREATE DATABASE `exampledb` /*!40100 DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci */ /*!80016 DEFAULT ENCRYPTION='N' */;
USE `exampledb`;

DROP TABLE IF EXISTS `foo`;
CREATE TABLE `foo` (
                       `id` int NOT NULL AUTO_INCREMENT,
                       `text` text,
                       PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

SET NAMES utf8mb4;

INSERT INTO `foo` (`id`, `text`) VALUES (1, 'test'), (2, 'next');
