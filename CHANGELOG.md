# Changelog

## 2.2.0-1.1.0 (upcoming)

* Pending changelog

## 2.2.0-1.0.0-c458ef0 (Built: May 23, 2018 | Pre-release)

* Fix security validation check
* Vault connection certificates are obtained dynamically
* KMS Utils dependency remove from Stratio Spark Dispatcher and History Server
* Possibility of specifying the name of the certificate within a directory with multiple certificates
* Add support to multiples CAs
* Added performance tests PNF
* Fix logs to be same as rest of Stratio platform
* Add messages for errors in Vault
* Add maximum retry limit for supervised drivers
* Support for MultiHDFS
* Fixed delegation tokens renewal time

## 2.2.0.5 (February 14, 2018)

* Fixed Supervise mode
* Separate stderr and stdout in dispatcher
* Fix history server stderr/stdout. Now is possible to set log level through SPARK_LOG_LEVEL
* Removed mesos security from History Server and unified environment variable VAULT_HOSTS
* Secret folder path configurable
* Changed log format according to Stratio standards
* Mesos Role no longer obtain mesos pricipal and mesos secret from vault in Spark jobs

## 2.2.0.4 (January 11, 2018)

* Added Tenant Name variable being able to have Spark Dispatcher with different name
* Enable Debug mode
* Support Dynamic allocation with Calico (External shuffle working in HOST mode)

## 2.2.0.3 (December 27, 2017)

* Unify Vault variables
* Secret Broadcast variables (Experimental)

## 2.2.0.2 (December 26, 2017)

* Added mesos constraints management to spark driver
* Added a secure way to retrieve user and passwords information from vault
* History Server could read from HDFS in HA using environment variables
* Added validation to curl parameters

## 2.2.0.1 (November 06, 2017)

* Removed Mesos secret and principal from curls
* Added configurable HDFS timeout

## 2.2.0.0 (September 27, 2017)

* Connection to Elastic with TLS
* Connection to Postgres with TLS, unified in datastore identity
* Removed Kafka identity, unified in datastore identity
* Removed script connection to Postgres 

## 2.1.0.7 (January 22, 2018)

* Supervise mode fixed

## 2.1.0.6 (December 21, 2017)

* Added validation to curl parameters
* Added mesos constraints management to spark driver
* Added a secure way to retrieve user and passwords information from vault
* Added Tenant Name variable being able to have Spark Dispatcher with different name

## 2.1.0.5 (November 07, 2017)

* Connection to Elastic with TLS
* Connection to Postgres with TLS, unified in datastore identity
* Removed Kafka identity, unified in datastore identity
* Removed script connection to Postgres 
* Removed Mesos secret and principal from curls
* Added configurable HDFS timeout

## 2.1.0.4 (August 17, 2017)

* Spark Dispatcher retrieves Mesos Principal and Secret from Vault

## 2.1.0.3 (July 26, 2017)

* Fix History Server env vars

## 2.1.0.2 (July 25, 2017)

* Dynamic Authentication for History Server
* SDN compatibility and isolation for History Server

## 2.1.0.1 (July 18, 2017)

* Refactor vault variables

## 2.1.0.0 (July 13, 2017)

* Spark-vault interactions
* SDN compatibility and isolation
* Kerberized access to hdfs
* Postgress TLS connection
* Dynamic Authentication
* Stratio Mesos security compatibility
* Initial Stratio Version of Spark
* Forked from Apache Spark 2.1.0
