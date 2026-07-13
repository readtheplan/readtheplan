class FixtureResource < Inspec.resource(1)
  name 'fixture_resource'

  def dangerous
    system('fixture-command')
  end
end
