chef_server_url 'https://chef-control.example.invalid/organizations/production'
node_name 'workstation-admin'
client_key '/home/operator/.chef/workstation-admin.pem'
ssl_verify_mode :verify_none
knife[:ssh_user] = 'bootstrap'
knife[:ssh_password] = 'fixture-chef-ssh-password'
knife[:forward_agent] = true
knife[:yes] = true
knife[:secret] = 'fixture-chef-data-bag-secret'
knife[:bootstrap_proxy] = 'http://fixture-bootstrap-user:fixture-bootstrap-pass@proxy.example.invalid:8080'
knife[:bootstrap_version] = ''
knife[:editor] = 'vim'
