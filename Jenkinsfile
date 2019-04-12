pipeline {
  agent any
  stages {
    stage('build') {
      steps {
        sshScript(script: '/var/lib/vyos-build/pkg-build.sh', failOnError: true)
      }
    }
  }
}