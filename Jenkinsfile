pipeline {
  agent any
  stages {
    stage('build') {
      agent {
        node {
          label 'jessie-amd64'
        }

      }
      steps {
        sh '''


/var/lib/vyos-build/pkg-build.sh'''
      }
    }
  }
}