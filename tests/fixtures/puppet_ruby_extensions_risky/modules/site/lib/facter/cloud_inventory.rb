require 'facter'
require 'net/http'
require 'yaml'

Facter.add(:cloud_inventory) do
  setcode do
    api_token = ENV['RTP_FIXTURE_PUPPET_FACT_SECRET_DO_NOT_LEAK']
    response = Net::HTTP.get(URI.parse('https://facts.example.invalid/v1'))
    YAML.load(response)
  end
end
