cookbook_path ['/srv/chef/cookbooks', '/srv/chef/site-cookbooks']
data_bag_path '/srv/chef/data_bags'
environment 'production'
json_attribs '/srv/chef/node.json'
recipe_url 'https://cookbooks.example.invalid/production.tar.gz'
data_collector.server_url 'https://automate.example.invalid/data-collector/v0'
data_collector.token = 'fixture-chef-solo-collector-token'
log_level :debug
umask 0000
solo true
