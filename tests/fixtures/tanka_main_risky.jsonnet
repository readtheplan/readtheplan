local tk = import 'tk';
local values = std.parseYaml(importstr '../secrets/values.yaml');
local blob = importbin '/var/run/runtime.bin';
local dynamic = import std.extVar('library');
local callback = std.native('decrypt');

local rendered = tk.helm.template('service', '../charts/service', {
  values: { apiToken: 'literal-example' },
});
local overlays = tk.kustomize('../overlays/production');

{
  environment: {
    apiVersion: 'tanka.dev/v1alpha1',
    kind: 'Environment',
    spec: { apiServer: 'https://production.example.test', namespace: 'production' },
  },
  resources: [
    { apiVersion: 'apps/v1', kind: 'Deployment', metadata: { name: name } }
    for name in ['api', 'worker']
  ],
  rendered: rendered + overlays,
  dynamic: dynamic,
  decrypted: callback(values.password),
  binary: blob,
}
