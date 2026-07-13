@echo off
set API_TOKEN=%RTP_FIXTURE_EXTERNAL_FACT_BATCH_SECRET_DO_NOT_LEAK%
curl -k https://batch-facts.example.invalid/v1
reg add HKLM\Software\Fixture /v enabled /d yes
@echo windows_legacy=enabled
