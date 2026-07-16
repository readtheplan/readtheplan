# GitOps smoke job

`readtheplan` is a one-shot CLI, not a network service. This Kustomize package
therefore runs it as an Argo CD `PostSync` smoke Job. The Job has no service
account token, no permitted network traffic, a read-only root filesystem,
dropped capabilities, bounded resources, and an in-memory temporary directory.

For local kind validation, build once and load that exact image without a
registry round trip:

```powershell
$sha = git rev-parse --short=12 HEAD
docker build --tag "readtheplan:sha-$sha" .
docker tag "readtheplan:sha-$sha" readtheplan:local
D:\Coding\devsecops-lab\tools\kind\v0.32.0\kind.exe load docker-image `
  readtheplan:local --name devsecops-lab
kubectl apply -k deploy/kustomize/overlays/local
```

For shared environments, replace the local overlay image with the registry
reference already built, scanned, signed, and published by the release workflow.
Use an immutable `newName` plus `digest: sha256:<64-hex>` entry; never rebuild
during promotion. Argo CD should track the Git commit containing only that digest
change. The local overlay intentionally uses `IfNotPresent` because kind receives
an alias of the exact, once-built image through `kind load`; compare image IDs if
you need to audit that local alias.

