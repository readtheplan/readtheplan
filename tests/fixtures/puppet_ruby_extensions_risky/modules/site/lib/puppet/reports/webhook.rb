require 'net/http'
require 'openssl'
require 'puppet'

Puppet::Reports.register_report(:webhook) do
  desc 'Forward reports to the fixture service.'

  def process
    api_token = ENV['RTP_FIXTURE_PUPPET_REPORT_SECRET_DO_NOT_LEAK']
    http = Net::HTTP.new('reports.example.invalid', 443)
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE
    http.post('/reports', self.to_yaml, 'Authorization' => api_token)
  end
end
