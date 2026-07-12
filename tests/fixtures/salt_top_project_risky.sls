base:
  '*':
    - baseline
    - users
  'G@role:web and E@web-[0-9]+':
    - match: compound
    - webserver
prod:
  group1:
    - match: nodegroup
    - hardened
