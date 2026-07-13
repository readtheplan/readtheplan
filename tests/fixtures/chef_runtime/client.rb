chef_server_url 'http://chef-control.example.invalid/organizations/production'
node_name 'production-node'
client_key '/etc/chef/client.pem'
ssl_verify_mode :verify_none
verify_api_cert false
http_proxy 'http://fixture-chef-proxy-user:fixture-chef-proxy-pass@proxy.example.invalid:8080'
https_proxy_pass 'fixture-chef-https-proxy-password'
data_collector.server_url 'http://automate.example.invalid/data-collector/v0'
data_collector.token = 'fixture-chef-data-collector-token'
file_atomic_update false
data_bag_decrypt_minimum_version 2
log_level :debug
umask 0000
interval 300
add_formatter :nyan
local_mode true
system('fixture-chef-client-command-do-not-expose')
