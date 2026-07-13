#!/bin/bash
pkg_name=fixture-service
pkg_origin=fixture-origin
pkg_version=$(curl -s http://version.example.invalid/latest)
pkg_source=http://fixture-user:fixture-password@example.invalid/source-${pkg_version}.tar.gz
pkg_shasum=""
pkg_deps=(core/glibc fixture/database/1.2.3/20260101010101)
pkg_build_deps=(core/gcc)
pkg_svc_user=root
pkg_svc_run="bash -c run-fixture-service"
pkg_exports=([port]=server.port)
pkg_exposes=(port)
pkg_binds=([database]="host port")
pkg_binds_optional=([cache]="host port")
pkg_shutdown_signal=KILL
HAB_AUTH_TOKEN=fixture-habitat-auth-token-do-not-leak

do_download() {
  curl -k http://downloads.example.invalid/archive -o source.tar.gz
}

do_verify() {
  return 0
}

do_build() {
  sudo ./configure
  chmod 777 ./fixture-binary
  ssh fixture-host.example.invalid build-remotely
}

do_install() {
  rm -rf /tmp/fixture-build
  hab pkg upload results/fixture.hart
  echo "token=$HAB_AUTH_TOKEN"
}
