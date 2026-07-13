@Grab('org.example:fixture-controller-helper:1.0')
import groovy.transform.Field
import jenkins.model.Jenkins

@Field List deployments = []

def call(Map config = [:]) {
    def apiToken = 'fixture-shared-library-secret-do-not-leak'
    withCredentials([string(credentialsId: 'fixture-jenkins-credential-do-not-leak', variable: 'TOKEN')]) {
        sh "deploy --target ${config.target}"
    }
    def payload = libraryResource(config.resourcePath)
    Jenkins.instance.getItemByFullName('fixture-job-name-do-not-leak')
    currentBuild.rawBuild.getExecutor()
    new URL('https://shared-library.example.invalid/hook').openConnection()
    pipeline {
        agent any
    }
    return payload
}
