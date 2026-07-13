package org.example

import hudson.model.Run
import groovy.transform.NonCPS

class Helper {
    def steps

    @NonCPS
    def evaluatePayload(value) {
        new GroovyShell().evaluate(value)
    }

    def runCommand(command) {
        Runtime.getRuntime().exec(command)
        new File('fixture-controller-path-do-not-leak').text = command
        Class.forName('fixture.dynamic.Type')
    }
}
