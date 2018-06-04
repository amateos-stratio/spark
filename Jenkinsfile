@Library('libpipelines@master') _

hose {
    MAIL = 'support'
    SLACKTEAM = 'stratiosecurity'
    MODULE = 'stratio-spark'
    REPOSITORY = 'spark'
    DEVTIMEOUT = 300
    RELEASETIMEOUT = 200
    BUILDTOOLVERSION = '3.5.0'
    MAVEN_THREADSPERCORE = 2
    PKGMODULESNAMES = ['stratio-spark']

    NEW_VERSIONING = true
    FREESTYLE_BRANCHING = true

    DEV = { config ->

        doPackage(config)
        doUT(config)
        parallel(DOCKER1: {
                    doDocker(conf: config, dockerfile:"DockerfileDispatcher")
                },DOCKER2: {
                    doDocker(conf: config, dockerfile:"DockerfileDriver", image:"spark-stratio-driver")
                }, DEPLOY: {
                    doDeploy(config)
                }, DOCKER3: {
                     doDocker(conf: config, dockerfile:"DockerfileHistory", image:"spark-stratio-history-server")
        }, failFast: config.FAILFAST)
     }


    INSTALLSERVICES = [
            ['DCOSCLI':   ['image': 'stratio/dcos-cli:0.4.15-SNAPSHOT',
                           'volumes': ['stratio/paasintegrationpem:0.1.0'],
                           'env':     ['DCOS_IP=10.200.0.156',
                                      'SSL=true',
                                      'SSH=true',
                                      'TOKEN_AUTHENTICATION=true',
                                      'DCOS_USER=admin@demo.stratio.com',
                                      'DCOS_PASSWORD=1234',
                                      'BOOTSTRAP_USER=operador',
                                      'PEM_FILE_PATH=/paascerts/PaasIntegration.pem'],
                           'sleep':  120,
			   'healthcheck': 5000]]
        ]

    INSTALLPARAMETERS = """
        | -DDCOS_CLI_HOST=%%DCOSCLI#0
        | -DDCOS_IP=10.200.0.156
        | -DPEM_PATH=paascerts/PaasIntegration.pem
        | -DBOOTSTRAP_IP=10.200.0.155
        | -DSPARK_DOCKER_IMAGE=qa.stratio.com/stratio/stratio-spark
        | -DSPARK_HISTORY_SERVER_DOCKER_IMAGE=qa.stratio.com/stratio/spark-stratio-history-server
        | -DSPARK_DRIVER_DOCKER_IMAGE=qa.stratio.com/stratio/spark-stratio-driver
        | -DSTRATIO_SPARK_VERSION=%%VERSION
        | -DCLUSTER_ID=nightly
        | -DSPARK_COVERAGE_IMAGE=qa.stratio.com/stratio/stratio-spark-coverage
        | -DCOVERAGE_VERSION=0.2.0-SNAPSHOT
        | -DSPARK_FW_NAME=spark-fw
        | -DPOSTGRES_INSTANCE=pg-0001-postgrestls.service.paas.labs.stratio.com:5432/postgres
        | """.stripMargin().stripIndent()

    INSTALL = { config, params ->
      def ENVIRONMENTMAP = stringToMap(params.ENVIRONMENT)      

      if (config.INSTALLPARAMETERS.contains('GROUPS_SPARK')) {
      	config.INSTALLPARAMETERS = "${config.INSTALLPARAMETERS}".replaceAll('-DGROUPS_SPARK', '-Dgroups')
	doAT(conf: config)
      } else {
      	doAT(conf: config)
      }
    }

}
