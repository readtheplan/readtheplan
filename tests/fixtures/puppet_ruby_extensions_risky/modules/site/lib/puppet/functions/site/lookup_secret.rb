Puppet::Functions.create_function(:'site::lookup_secret') do
  dispatch :lookup_secret do
    param 'String', :name
  end

  def lookup_secret(name)
    api_token = ENV['RTP_FIXTURE_PUPPET_FUNCTION_SECRET_DO_NOT_LEAK']
    value = eval(name)
    File.write('/tmp/puppet-function-cache', value)
    value
  end
end
