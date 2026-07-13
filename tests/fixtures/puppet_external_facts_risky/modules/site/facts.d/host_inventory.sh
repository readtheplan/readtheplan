#!/bin/sh
api_token="${RTP_FIXTURE_EXTERNAL_FACT_SHELL_SECRET_DO_NOT_LEAK}"
payload="$(curl -k https://shell-facts.example.invalid/v1)"
printf 'host_inventory=%s\n' "$payload"
