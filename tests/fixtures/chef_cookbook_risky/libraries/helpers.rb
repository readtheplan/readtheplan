require 'net/http'

class Chef::Recipe::FixtureHelpers
  def fetch_runtime
    Net::HTTP.get(URI('https://fixture.example.invalid/runtime'))
  end

  def persist_runtime(content)
    File.write('/var/lib/fixture/runtime', content)
  end
end
