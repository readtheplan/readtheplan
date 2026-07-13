api_fqdn 'chef-control.example.invalid'
nginx['enable_non_ssl'] = true
nginx['ssl_protocols'] = 'TLSv1 TLSv1.2'
nginx['ssl_ciphers'] = 'HIGH:RC4'
insecure_addon_compat true
ldap['host'] = 'ldap.example.invalid'
ldap['port'] = 389
ldap['tls_enabled'] = false
ldap['bind_dn'] = 'CN=chef-reader,OU=Service Accounts,DC=example,DC=invalid'
ldap['bind_password'] = 'fixture-chef-ldap-password'
postgresql['sslmode'] = 'disable'
required_recipe['enable'] = true
required_recipe['path'] = '/etc/opscode/required.rb'
bookshelf['secret_access_key'] = 'fixture-chef-bookshelf-secret'
opscode_erchef['strict_search_result_acls'] = false
fips false
system('fixture-chef-server-command-do-not-expose')
