#!/usr/bin/env ruby
require 'net/http'
require 'yaml'

api_token = ENV['RTP_FIXTURE_EXTERNAL_FACT_RUBY_SECRET_DO_NOT_LEAK']
response = Net::HTTP.get(URI('https://ruby-facts.example.invalid/v1'))
puts YAML.load(response)
