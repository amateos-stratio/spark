@rest
Feature: [Fault Tolerance test] Executor Dropdowns

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

  Scenario:[Kafka Executor Dropdowns][01] Launch Kafka job, and kill executor to check if another is launched

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

    #Wait until the executor is running
    Then in less than '200' seconds, checking each '10' seconds, the command output 'curl -s !{MESOS_MASTER}:5050/frameworks | jq '.frameworks[] | select((.name | contains("AT-kafka")) and (.id | contains("!{driverKafka}"))) | .tasks | .[] | .state' | grep "TASK_RUNNING" ' contains 'RUNNING'

    #Get the host where the Executor is deployed
    Then I run 'curl -s !{MESOS_MASTER}:5050/frameworks | jq '.frameworks[] | select((.name | contains("AT-kafka")) and (.id | contains("!{driverKafka}"))) | .tasks | .[] |.slave_id' | tr -d '"'' in the ssh connection and save the value in environment variable 'SLAVE_ID'
    Then I run 'curl -s !{MESOS_MASTER}:5050/slaves | jq '.slaves[] | select(.id=="!{SLAVE_ID}") | .hostname' | tr -d '"'' in the ssh connection and save the value in environment variable 'EXECUTOR_IP'

    #Ssh into the host, get Spark docker executor and kill them
    Then I run 'echo !{EXECUTOR_IP}' in the ssh connection
    Then I open a ssh connection to '!{EXECUTOR_IP}' with user 'root' and password 'stratio'

    #Wait first for having a running docker
    Then I run 'docker ps | grep ${SPARK_DRIVER_DOCKER_IMAGE:-qa.stratio.com/stratio/spark-stratio-driver}:${STRATIO_SPARK_VERSION} | cut -d ' ' -f 1 | while read x; do cmd=$(docker inspect $x | jq '.[]|.Config.Env'); echo $x $cmd; done | grep org.apache.spark.executor.CoarseGrainedExecutorBackend | cut -d ' ' -f 1' in the ssh connection and save the value in environment variable 'DOCKER_ID'
    Then I run 'docker rm -f !{DOCKER_ID}' in the ssh connection

    #Check there are a TASK_FAILED (killed by us)
    Then in less than '200' seconds, checking each '10' seconds, the command output 'curl -s !{MESOS_MASTER}:5050/frameworks | jq '.frameworks[] | select((.name | contains("AT-kafka")) and (.id | contains("!{driverKafka}"))) | .completed_tasks | .[] | .state' | grep FAILED | wc -l' contains '1'

    #Check a new Task has launched
    Then in less than '200' seconds, checking each '10' seconds, the command output 'curl -s !{MESOS_MASTER}:5050/frameworks | jq '.frameworks[] | select((.name | contains("AT-kafka")) and (.id | contains("!{driverKafka}"))) | .tasks | .[] | .state'' contains 'TASK_RUNNING'

    #Check we are processing windows, getting an initial value, and seeing if it's being incremented after few seconds
    Given I open a ssh connection to '${DCOS_CLI_HOST}' with user 'root' and password 'stratio'
    Then I run 'dcos task log !{driverKafka} stdout --lines=1000000 | grep "###" | wc -l' in the ssh connection and save the value in environment variable 'PREVIOUS_WINDOW'
    Then in less than '100' seconds, checking each '10' seconds, the command output 'if [ $(dcos task log !{driverKafka} stdout --lines=1000000 | grep "###" | wc -l) -gt "!{PREVIOUS_WINDOW}" ]; then echo "true"; fi' contains 'true'

    #Now kill the process
    #(We send a JSON because the step from cucumber, doesn't support empty posts submissions)
    Then I set sso token using host '${CLUSTER_ID}.labs.stratio.com' with user 'admin' and password '1234'
    Then I securely send requests to '${CLUSTER_ID}.labs.stratio.com:443'
    Then I send a 'POST' request to '/service/${SPARK_FW_NAME}/v1/submissions/kill/!{driverKafka}' based on 'schemas/pf/SparkCoverage/kafka_curl.json' as 'json' with:
      |   $.appResource  |  UPDATE  | http://spark-coverage.marathon.mesos:9000/jobs/kafka-${COVERAGE_VERSION}.jar | n/a     |

    Then the service response status must be '200' and its response must contain the text '"success" : true'

    #Check exit is clean
    Then in less than '200' seconds, checking each '10' seconds, the command output 'curl -s !{MESOS_MASTER}:5050/frameworks | jq '.frameworks[] | select(.name == "${SPARK_FW_NAME}") | .completed_tasks |  map(select(.name | contains ("AT-kafka"))) | map(select(.id == "!{driverKafka}")) | .[] | .state' | grep "TASK_KILLED" | wc -l' contains '1'

    Then in less than '10' seconds, checking each '5' seconds, the command output 'curl -s !{MESOS_MASTER}:5050/frameworks | jq '.frameworks[] | select(.name == "${SPARK_FW_NAME}") | .completed_tasks |  map(select(.name | contains ("AT-kafka"))) | map(select(.id == "!{driverKafka}")) | .[] | .statuses' | grep "TASK_RUNNING"  | wc -l' contains '1'
    Then in less than '10' seconds, checking each '5' seconds, the command output 'curl -s !{MESOS_MASTER}:5050/frameworks | jq '.frameworks[] | select(.name == "${SPARK_FW_NAME}") | .completed_tasks |  map(select(.name | contains ("AT-kafka"))) | map(select(.id == "!{driverKafka}")) | .[] | .statuses' | grep "TASK_FAILED"  | wc -l' contains '0'
    Then in less than '10' seconds, checking each '5' seconds, the command output 'curl -s !{MESOS_MASTER}:5050/frameworks | jq '.frameworks[] | select(.name == "${SPARK_FW_NAME}") | .completed_tasks |  map(select(.name | contains ("AT-kafka"))) | map(select(.id == "!{driverKafka}")) | .[] | .statuses' | grep "TASK_KILLED"  | wc -l' contains '1'



