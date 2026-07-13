require "ohai/mixin/shell_out"
require "net/http"

Ohai.plugin(:Hostname) do
  provides "hostname", "platform_inventory/api_token"
  depends "network"

  def inventory_endpoint
    ENV["FIXTURE_OHAI_ENDPOINT"]
  end

  collect_data(:linux) do
    hint = hint?("platform_inventory")
    command_output = shell_out!("fixture-ohai-inventory --json").stdout
    response = Net::HTTP.get(URI.parse(inventory_endpoint))
    local_inventory = File.read("/etc/fixture/inventory.json")
    File.write("/tmp/fixture-ohai-marker", command_output)
    api_token = "fixture-ohai-secret-do-not-leak"
    Ohai::Log.info("api_token=#{api_token}")

    platform_inventory Mash.new
    platform_inventory[:hint] = hint
    platform_inventory[:remote] = response
    platform_inventory[:local] = local_inventory
    platform_inventory[:api_token] = api_token
    hostname command_output
  end
end
