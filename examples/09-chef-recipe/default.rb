log 'Preparing the web server'

package 'nginx' do
  action :install
end

service 'nginx' do
  action [:enable, :restart]
end

execute 'database migration' do
  command './manage.py migrate'
end
