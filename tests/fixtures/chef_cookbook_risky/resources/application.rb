unified_mode true

property :api_token, String
property :config_path, String, default: '/etc/fixture.conf'

load_current_value do
  shell_out!('fixturectl status')
end

action :create do
  file new_resource.config_path do
    mode '0640'
    action :create
  end
  system('fixturectl reload')
end
