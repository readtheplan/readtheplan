include_recipe 'organization::baseline'

remote_file '/tmp/installer.sh' do
  source 'http://downloads.example.com/installer.sh'
  action :create
end

user 'deploy' do
  groups ['sudo']
  action :create
end

cron 'nightly-deploy' do
  command '/srv/deploy'
  minute '0'
  hour '2'
end

systemd_unit 'application.service' do
  content({ Unit: { Description: 'application' }, Service: { ExecStart: '/srv/app' } })
  action [:create, :restart]
end

template '/etc/application.conf' do
  source 'application.conf.erb'
  mode '0777'
  notifies :restart, 'service[application]', :immediately
end

execute 'database migration' do
  command '/srv/migrate'
  only_if '/usr/bin/test -f /srv/ready'
end

log 'rollout configured'
