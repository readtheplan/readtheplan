#!/usr/bin/env perl
use HTTP::Tiny;

my $api_token = $ENV{'RTP_FIXTURE_EXTERNAL_FACT_PERL_SECRET_DO_NOT_LEAK'};
my $response = HTTP::Tiny->new()->get('https://perl-facts.example.invalid/v1');
print "legacy_inventory=$response->{content}\n";
