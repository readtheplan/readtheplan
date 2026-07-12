include:
  - common.logging

web-stack:
  pkg.installed:
    - name: nginx
  service.running:
    - name: nginx
    - require:
      - pkg: web-stack

/tmp/legacy.conf:
  file.absent: []

deploy-release:
  cmd.run:
    - name: /usr/local/bin/deploy
    - env:
        DEPLOY_TOKEN: __slot__:salt:pillar.get(deploy:token)
    - unless: test -f /var/lib/app/deployed

validation:
  test.nop:
    - comment: parsed only
