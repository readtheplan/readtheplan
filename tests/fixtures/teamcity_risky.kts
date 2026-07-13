import jetbrains.buildServer.configs.kotlin.*
import jetbrains.buildServer.configs.kotlin.buildSteps.script

version = "2026.1"

project {
    buildType(Deploy)
}

object Deploy : BuildType({
    name = "Deploy"
    params {
        password("env.DEPLOY_TOKEN", "credentialsJSON:example-token")
        param("env.API_TOKEN", "literal-teamcity-token")
    }
    vcs {
        root(PlatformRepo)
    }
    steps {
        script {
            scriptContent = "terraform apply -auto-approve"
        }
    }
    triggers {
        vcs { }
    }
    dependencies {
        snapshot(Compile) { }
    }
    requirements {
        equals("teamcity.agent.name", "production")
    }
    features {
        commitStatusPublisher { }
        swabra { }
    }
    artifactRules = "dist/**"
    image = "docker:latest"
})

object PlatformRepo : GitVcsRoot({
    url = "https://example.test/platform.git"
    authMethod = password {
        userName = "deploy"
        password = "credentialsJSON:repo-token"
    }
})

val generated = ProcessBuilder("sh", "-c", "echo generated").start()
val metadata = File(DslContext.baseDir, "metadata.json").readText()
