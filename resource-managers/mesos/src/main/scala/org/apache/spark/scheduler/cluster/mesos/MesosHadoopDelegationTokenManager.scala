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

package org.apache.spark.scheduler.cluster.mesos

import java.security.PrivilegedExceptionAction
import java.util.concurrent.{ScheduledExecutorService, TimeUnit}

import org.apache.hadoop.conf.Configuration
import org.apache.hadoop.security.UserGroupInformation
import org.apache.spark.SparkConf
import org.apache.spark.deploy.SparkHadoopUtil
import org.apache.spark.deploy.security.HadoopDelegationTokenManager
import org.apache.spark.internal.{Logging, config}
import org.apache.spark.rpc.RpcEndpointRef
import org.apache.spark.scheduler.KerberosUser
import org.apache.spark.scheduler.cluster.CoarseGrainedClusterMessages.UpdateDelegationTokens
import org.apache.spark.ui.UIUtils
import org.apache.spark.util.ThreadUtils

import scala.collection.mutable


/**
  * The MesosHadoopDelegationTokenManager fetches and updates Hadoop delegation tokens on the behalf
  * of the MesosCoarseGrainedSchedulerBackend. It is modeled after the YARN AMCredentialRenewer,
  * and similarly will renew the Credentials when 75% of the renewal interval has passed.
  * The principal difference is that instead of writing the new credentials to HDFS and
  * incrementing the timestamp of the file, the new credentials (called Tokens when they are
  * serialized) are broadcast to all running executors. On the executor side, when new Tokens are
  * received they overwrite the current credentials.
  */
private[spark] class MesosHadoopDelegationTokenManager(
                                                        conf: SparkConf,
                                                        ugisAndConfs: Map[String, (UserGroupInformation, Configuration)],
                                                        driverEndpoint: RpcEndpointRef)
  extends Logging {

  require(driverEndpoint != null, "DriverEndpoint is not initialized")

  private val credentialRenewerThread: ScheduledExecutorService =
    ThreadUtils.newDaemonSingleThreadScheduledExecutor("Credential Renewal Thread")

  private val tokenManagers: Map[String, HadoopDelegationTokenManager] = ugisAndConfs.map {
    case (host, (_, hadoopConf)) => host -> new HadoopDelegationTokenManager(conf, hadoopConf)
  }

  private val tokens: mutable.Map[String, (String, Array[Byte], Long)] = mutable.Map(
    ugisAndConfs.map {
      case (host, (ugi, hadoopConf)) =>
        try {
          val creds = ugi.getCredentials

          // First time. Initializing
          val rt = ugi.doAs(new PrivilegedExceptionAction[Long] {
            override def run(): Long =
              tokenManagers(host).obtainDelegationTokens(hadoopConf, creds)
          })

          logDebug(s"Initialized tokens for host $host " +
            s"with username: ${ugi.getUserName()}")
          host ->
            (
              ugi.getUserName(),
              SparkHadoopUtil.get.serialize(creds),
              SparkHadoopUtil.get.nextCredentialRenewalTime(rt, conf)
            )
        } catch {
          case e: Exception =>
            logError(s"Failed to fetch Hadoop delegation tokens for host $host: $e")
            throw e
        }
    }.toSeq: _*
  )

  // Run the renewal for each hdfs
  ugisAndConfs.keys.foreach(scheduleTokenRenewal)

  private def scheduleTokenRenewal(host: String): Unit = {


    def scheduleRenewal(runnable: Runnable): Unit = {
      val remainingTime = tokens(host)._3 - System.currentTimeMillis()
      if (remainingTime <= 0) {
        logInfo("Credentials have expired, creating new ones now.")
        runnable.run()
      } else {
        logInfo(s"Scheduling login from keytab in $remainingTime millis.")
        credentialRenewerThread.schedule(runnable, remainingTime, TimeUnit.MILLISECONDS)
      }
    }

    val credentialRenewerRunnable =
      new Runnable {
        override def run(): Unit = {
          try {
            getNewDelegationTokens(host)
            val (principal, newToken, _) = tokens(host)
            broadcastDelegationTokens(host, principal, newToken)
          } catch {
            case e: Exception =>
              // Log the error and try to write new tokens back in an hour
              val delay = TimeUnit.SECONDS.toMillis(conf.get(config.CREDENTIALS_RENEWAL_RETRY_WAIT))
              logWarning(
                s"Couldn't broadcast tokens of host $host, " +
                  s"trying again in ${UIUtils.formatDuration(delay)}", e)
              credentialRenewerThread.schedule(this, delay, TimeUnit.MILLISECONDS)
              return
          }
          scheduleRenewal(this)
        }
      }
    scheduleRenewal(credentialRenewerRunnable)
  }

  private def getNewDelegationTokens(host: String): Unit = {

    // Get new delegation tokens by logging in with a new UGI inspired by AMCredentialRenewer.scala
    // Don't protect against keytabFile being empty because it's guarded above.
    val (ugi, hadoopConf) = ugisAndConfs(host)
    logInfo(s"Retrieved ugi and hadoopConf for host $host")
    val newUgi = KerberosUser.retrieveNewUgi(host)
    val tempCreds = newUgi.getCredentials
    val nextRenewalTime = newUgi.doAs(new PrivilegedExceptionAction[Long] {
      override def run(): Long = {
        tokenManagers(host).obtainDelegationTokens(hadoopConf, tempCreds)
      }
    })

    val currTime = System.currentTimeMillis()
    val timeOfNextRenewal = if (nextRenewalTime <= currTime) {
      logWarning(s"Next credential renewal time in host $host ($nextRenewalTime) is earlier than " +
        s"current time ($currTime), which is unexpected, please check your credential renewal " +
        "related configurations in the target services.")
      currTime
    } else {
      SparkHadoopUtil.get.nextCredentialRenewalTime(nextRenewalTime, conf)
    }
    logInfo(s"Time of next renewal is in ${timeOfNextRenewal - System.currentTimeMillis()} ms")

    // Add the temp credentials back to the original ones.
    ugi.addCredentials(tempCreds)

    // update tokens for late or dynamically added executors
    val updatedToken = SparkHadoopUtil.get.serialize(tempCreds)

    logInfo(s"Saving new tokens and renewal for host $host")
    tokens.put(host, (ugi.getUserName, updatedToken, timeOfNextRenewal))
  }

  private def broadcastDelegationTokens(host: String, principal: String, tokens: Array[Byte]) = {
    logInfo(s"Sending new tokens of host $host to all executors")
    driverEndpoint.send(UpdateDelegationTokens(host, principal, tokens))
  }

  def getAllTokens(): Map[String, (String, Array[Byte])] = {
    tokens.map {
      case (host, (principal, token, _)) =>
        host -> (principal, token)
    }
  } toMap
}
