require 'fileutils'
require 'puppet'

Puppet::Type.type(:managed_service).provide(:systemd) do
  commands :systemctl => '/bin/systemctl'

  def destroy
    system("#{command(:systemctl)} disable #{resource[:name]}")
    FileUtils.rm_rf("/etc/systemd/system/#{resource[:name]}.service.d")
  end
end
