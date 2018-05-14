/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.spark.security

import java.util.UUID

import scala.collection.mutable
import org.apache.hadoop.conf.Configuration
import org.apache.hadoop.fs.Path
import org.apache.hadoop.security.UserGroupInformation
import org.apache.spark.internal.Logging
import org.apache.spark.scheduler.KerberosUser
import org.apache.spark.security.HDFSConfig.downloadFile
import org.apache.spark.util.Utils


object MultiHDFSConfig extends Logging{

  // Here we have the pairs of ugis and configurations for each external hdfs
  private val multiHadoopPairs: mutable.Map[String, (UserGroupInformation, Configuration)] = mutable.Map.empty


  private[spark] def getUgisAndConfPerHost: Map[String, (UserGroupInformation, Configuration)] =
    multiHadoopPairs.toMap

  def getHadoopConfForHost(host: String): Option[Configuration] =
    multiHadoopPairs.get(host).map(_._2)

  private[spark] def getUgiForHost(host: String): Option[UserGroupInformation] =
    multiHadoopPairs.get(host).map(_._1)

  private val MULTI_HDFS_PREFIX = "MULTI_HDFS_"
  private val CONF_URI_SUFIX = "CONF_URI"
  private val KERBEROS_VAULT_PATH_SUFIX = "KERBEROS_VAULT_PATH"

  def prepareEnvironment(options: Map[String, String]): Map[String, String] = {

    val configurationIndexes: Seq[String] = options.foldLeft(Seq.empty[String]) {
      (accum, pairKeyValue) =>
        val key = pairKeyValue._1
        // Get the all the MULTI_HDFS_IDX_ indexes
        if ( key != "MULTI_HDFS_ENABLE" && key.startsWith(MULTI_HDFS_PREFIX)) {
          val idxPart = key.substring(0, key.indexOf("_", MULTI_HDFS_PREFIX.size) + 1)
          if (!accum.contains(idxPart)) {
            accum :+ idxPart
          } else {
            accum
          }
        } else {
          accum
        }
    }

    logInfo(s"Found this multiHdfs indexes: $configurationIndexes")

    require(configurationIndexes.size > 0,
      s"a proper MULTI_HDFS_X_( $CONF_URI_SUFIX & $KERBEROS_VAULT_PATH_SUFIX ) " +
        "must be configured to get MultiHadoop Configuration")

    val connectTimeout: Int = options.get("HDFS_CONF_CONNECT_TIMEOUT").getOrElse("5000").toInt
    val readTimeout: Int = options.get("HDFS_CONF_READ_TIMEOUT").getOrElse("5000").toInt

    configurationIndexes.foreach { index =>

      val configurationUri = options.get(index + CONF_URI_SUFIX)
      val vaultPathUri = options.get(index + KERBEROS_VAULT_PATH_SUFIX)

      require(configurationUri.isDefined, s"${index + CONF_URI_SUFIX} variable not provided")
      require(
        vaultPathUri.isDefined,
        s"${index + KERBEROS_VAULT_PATH_SUFIX} variable not provided"
      )

      val conf = getConfigurationFromUri(configurationUri.get, connectTimeout, readTimeout)
      val host = extractHDFSHostFromConf(conf)
      val (principal, keytab) = getUgiFromVaultPath(vaultPathUri.get)

      KerberosUser.addPrincipalAndKeytab(host, principal, keytab)

      logInfo(s"Downloaded multiHDFS keytab-principal for host $host")

      val ugi = UserGroupInformation.loginUserFromKeytabAndReturnUGI(
        principal,
        keytab)

      multiHadoopPairs.put(host, (ugi, conf))
      logInfo(s"Correctly processed MultiHDFS conf: $index* with hdfs host: $host")
    }

    Map.empty
  }

  def extractHDFSHostFromConf(conf: Configuration): String = {
    conf.get("fs.defaultFS").replace("hdfs://", "")
  }

  def extractHDFSHostFromPath(path: Option[String]): Option[String] = path.flatMap { p =>
    logDebug(s"Getting hdfs host for path: $path")
    val split = p.split("hdfs://")
    if (split.size > 1) {
      // we have a at least a route
      val pathWithoutHdfs = split.tail.head
      if (pathWithoutHdfs.startsWith("/")) {
        // Default HDFS avoid
        logDebug("Default HDFS")
        None
      } else {
        val hdfsHost = pathWithoutHdfs.split("/").head
        logDebug(s"Found HDFS HOST: $hdfsHost")
        Option(hdfsHost)
      }
    } else {
      logDebug("Path doesn't start with hdfs://")
      None
    }
  }

  private def getConfigurationFromUri(
                                       uri: String,
                                       connectTimeout: Int,
                                       readTimeout: Int
                                     ): Configuration = {

    val outputFolder = Utils.createTempDir("/tmp", "multihdfs")

    val coreSite = "core-site.xml"
    val hdfsSite = "hdfs-site.xml"

    downloadFile(uri, coreSite, outputFolder.getAbsolutePath, connectTimeout, readTimeout)
    downloadFile(uri, hdfsSite, outputFolder.getAbsolutePath, connectTimeout, readTimeout)

    val configuration = new Configuration(false)
    configuration.addResource(new Path(outputFolder.getAbsolutePath + Path.SEPARATOR + coreSite))
    configuration.addResource(new Path(outputFolder.getAbsolutePath + Path.SEPARATOR + hdfsSite))

    logInfo(s"Finished processing multi HDFS conf from $uri")
    configuration
  }

  private def getUgiFromVaultPath(kerberosVaultPath: String): (String, String) = {

    val (keytab64, principal) =
      VaultHelper.getKeytabPrincipalFromVault(kerberosVaultPath).get

    val pathToWrite = s"/tmp/${principal + UUID.randomUUID().toString}.keytab"

    val pathWritten = KerberosConfig.getKeytabPrincipal(keytab64, principal, pathToWrite)

    (principal, pathWritten)
  }

}
