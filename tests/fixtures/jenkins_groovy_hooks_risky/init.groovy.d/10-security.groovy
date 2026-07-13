import jenkins.model.Jenkins
import hudson.security.FullControlOnceLoggedInAuthorizationStrategy
import com.cloudbees.plugins.credentials.SystemCredentialsProvider

def controller = Jenkins.get()
def apiToken = 'fixture-controller-token-do-not-leak'
def endpoint = System.getenv('FIXTURE_ENDPOINT')

controller.setAuthorizationStrategy(new FullControlOnceLoggedInAuthorizationStrategy(false))
SystemCredentialsProvider.getInstance().getStore().addCredentials(domain, credential)
controller.pluginManager.getPlugin('mailer').disable()
controller.addNode(dynamicAgent)
new File('/var/lib/jenkins/bootstrap').text = new URL(endpoint).text
Runtime.getRuntime().exec('fixture-controller-command-do-not-run')
controller.save()
