control 'fixture-control-id' do
  impact 0.0
  title 'Skipped control'
  only_if { ENV['RUN_FIXTURE'] == 'yes' }
  describe command('curl -H "Authorization: fixture-token" http://example.invalid') do
    its('exit_status') { should eq 0 }
  end
end

control 'remote-control-id' do
  impact 1.0
  describe.one do
    describe http('https://example.invalid') do
      its('status') { should cmp 200 }
    end
  end
end

include_controls 'baseline-profile' do
  skip_control 'baseline-control-id'
end

require './fixture-helper'
