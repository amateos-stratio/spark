@rest
Feature: [Fault Tolerance test] Driver supervise false

  Background:

    Given I open a ssh connection to '${DCOS_CLI_HOST}' with user 'root' and password 'stratio'
    #Check dispatcher and spark-coverage are deployed
    Then in less than '20' seconds, checking each '10' seconds, the command output 'dcos task | grep "${SPARK_FW_NAME}\." | grep R | wc -l' contains '1'
    Then in less than '20' seconds, checking each '10' seconds, the command output 'dcos task | grep spark-coverage | grep R | wc -l' contains '1'

    #Obtain mesos master
    Given I open a ssh connection to '${DCOS_IP}' with user 'root' and password 'stratio'
    Given I run 'getent hosts leader.mesos | awk '{print $1}'' in the ssh connection and save the value in environment variable 'MESOS_MASTER'

    #Clean all drivers from spark-dispatcher
    Then I clean all the drivers in the dispatcher with name '${SPARK_FW_NAME}' in dcos host '${CLUSTER_ID}.labs.stratio.com' with mesos master '!{MESOS_MASTER}:5050' with user 'admin' and password '1234'

  Scenario:[Driver Supervise False][01] Launch Kafka Job, Kill the docker of the driver, the driver is not relaunched

    #Now launch the work
    Given I set sso token using host '${CLUSTER_ID}.labs.stratio.com' with user 'admin' and password '1234'
    And I securely send requests to '${CLUSTER_ID}.labs.stratio.com:443'

    When I send a 'POST' request to '/service/${SPARK_FW_NAME}/v1/submissions/create' based on 'schemas/pf/SparkCoverage/kafka_curl.json' as 'json' with:
      |   $.appResource  |  UPDATE  | http://spark-coverage.marathon.mesos:9000/jobs/kafka-${COVERAGE_VERSION}.jar | n/a     |
      |   $.sparkProperties['spark.jars']  |  UPDATE  | http://spark-coverage.marathon.mesos:9000/jobs/kafka-${COVERAGE_VERSION}.jar | n/a     |
      |   $.sparkProperties['spark.mesos.executor.docker.image']  |  UPDATE  | ${SPARK_DRIVER_DOCKER_IMAGE:-qa.stratio.com/stratio/spark-stratio-driver}:${STRATIO_SPARK_VERSION} | n/a     |
      |   $.appArgs[0]  |  UPDATE  | gosec1.node.paas.labs.stratio.com:9092 | n/a     |

    Then the service response status must be '200' and its response must contain the text '"success" : true'

    #Save the driver launched id
    Then I save the value from field in service response 'submissionId' in variable 'driverKafka'

    #Wait until the driver is running
    Then in less than '200' seconds, checking each '10' seconds, the command output 'curl -s !{MESOS_MASTER}:5050/frameworks | jq '.frameworks[] | select(.name == "${SPARK_FW_NAME}") | .tasks |  map(select(.name | contains ("AT-kafka"))) | map(select(.id == "!{driverKafka}")) | .[] | .state' | grep "TASK_RUNNING" | wc -l' contains '1'

    #Get the host where the driver is deployed
    Then I run 'curl -s !{MESOS_MASTER}:5050/frameworks | jq '.frameworks[] | select(.name == "${SPARK_FW_NAME}") | .tasks |  map(select(.name | contains ("AT-kafka"))) | map(select(.id == "!{driverKafka}")) | .[] | .slave_id' | tr -d '"'' in the ssh connection and save the value in environment variable 'SLAVE_ID'
    Then I run 'curl -s !{MESOS_MASTER}:5050/slaves | jq '.slaves[] | select(.id=="!{SLAVE_ID}") | .hostname' | tr -d '"'' in the ssh connection and save the value in environment variable 'DRIVER_IP'

    #Ssh into the host, get Spark docker driver and kill them
    Then I run 'echo !{DRIVER_IP}' in the ssh connection
    Then I open a ssh connection to '!{DRIVER_IP}' with user 'root' and password 'stratio'

    #Wait first for having a running docker and rm them
    Then I run 'docker ps | grep ${SPARK_DRIVER_DOCKER_IMAGE:-qa.stratio.com/stratio/spark-stratio-driver}:${STRATIO_SPARK_VERSION} | cut -d ' ' -f 1 | while read x; do cmd=$(docker inspect $x | jq '.[]|.Config.Env'); echo $x $cmd; done | grep -m 1 "/bin/spark-submit" | cut -d ' ' -f 1' in the ssh connection and save the value in environment variable 'DOCKER_ID'
    Then I run 'docker rm -f !{DOCKER_ID}' in the ssh connection

    #Check the driver is killed (not relaunched)
    Then in less than '200' seconds, checking each '10' seconds, the command output 'curl -s !{MESOS_MASTER}:5050/frameworks | jq '.frameworks[] | select(.name == "${SPARK_FW_NAME}") | .completed_tasks |  map(select(.name | contains ("AT-kafka"))) | map(select(.id == "!{driverKafka}")) | .[] | .state'' contains 'TASK_FAILED'

    #The spark-fw returned a finished status for the driver
    Given I set sso token using host '${CLUSTER_ID}.labs.stratio.com' with user 'admin' and password '1234'
    And I securely send requests to '${CLUSTER_ID}.labs.stratio.com:443'
    Then I send a 'GET' request to '/service/${SPARK_FW_NAME}/v1/submissions/status/!{driverKafka}'
    Then the service response status must be '200' and its response must contain the text '"driverState" : "FINISHED"'