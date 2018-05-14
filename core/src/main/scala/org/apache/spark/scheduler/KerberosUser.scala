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

package org.apache.spark.scheduler

import org.apache.hadoop.conf.Configuration
import org.apache.hadoop.security.UserGroupInformation
import org.apache.spark.SparkConf
import org.apache.spark.deploy.SparkHadoopUtil
import org.apache.spark.internal.Logging
import org.apache.spark.security.MultiHDFSConfig

import scala.collection.mutable
import scala.util.Try

object KerberosUser extends Logging {

  private var conf: Option[Configuration] = None
  private var ugi: Option[UserGroupInformation] = None
  private val principalAndKeytabsCollection: mutable.Map[String, (String, String)] =
    mutable.Map.empty

  private[spark] def addPrincipalAndKeytab(
                                            host: String,
                                            principal: String,
                                            keytab: String
                                          ): Unit = {
    principalAndKeytabsCollection.put(host, (principal, keytab))
  }

  private[spark] def retrieveNewUgi(host: String): UserGroupInformation = {
    val (principal, keytab) = principalAndKeytabsCollection(host)
    UserGroupInformation.loginUserFromKeytabAndReturnUGI(principal, keytab)
  }

  def securize (principal: String, keytab: String) : Unit = {
    val hadoopConf = SparkHadoopUtil.get.newConfiguration(new SparkConf())
    hadoopConf.set("hadoop.security.authentication", "Kerberos")
    UserGroupInformation.setConfiguration(hadoopConf)
    UserGroupInformation.loginUserFromKeytab(principal, keytab)
    conf = Option(hadoopConf)
    ugi = Option(UserGroupInformation.getLoginUser)
    addPrincipalAndKeytab(
      host = MultiHDFSConfig.extractHDFSHostFromConf(hadoopConf),
      principal,
      keytab
    )
  }

  private[spark] def baseUgiAndConf: Option[(UserGroupInformation, Configuration)] =
    for {
      finalUgi <- ugi
      finalConf <- conf
    } yield(finalUgi, finalConf)

}