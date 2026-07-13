$pkg_name="fixture-windows-service"
$pkg_origin="fixture-origin"
$pkg_version="1.0.0"
$pkg_source="http://fixture-user:fixture-password@example.invalid/source.zip"
$pkg_deps=@(
  "core/windows-service"
  "fixture/runtime/1.0.0/20260101010101"
)
$pkg_build_deps=@("core/visual-build-tools")
$pkg_svc_user="SYSTEM"
$pkg_svc_run="powershell.exe -EncodedCommand Zml4dHVyZQ=="
$HAB_AUTH_TOKEN="fixture-habitat-windows-token-do-not-leak"

Function Invoke-Download {
  Invoke-WebRequest -Uri "http://downloads.example.invalid/archive.zip" -OutFile source.zip
}

Function Invoke-Verify {
  return 0
}

Function Invoke-Build {
  Start-Process build.exe -Verb RunAs
  Remove-Item -Recurse -Force C:\fixture-build
}
