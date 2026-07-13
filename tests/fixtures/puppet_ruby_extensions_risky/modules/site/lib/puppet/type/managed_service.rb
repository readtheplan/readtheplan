require 'puppet'

Puppet::Type.newtype(:managed_service) do
  desc 'system("ignored") and Net::HTTP are examples, not calls'

  newparam(:name, namevar: true) do
    validate do |value|
      raise ArgumentError, 'name is required' if value.empty?
    end
  end
end
