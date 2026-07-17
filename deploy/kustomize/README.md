# GitOps smoke job

`readtheplan` is a one-shot CLI, not a network service. This Kustomize package
therefore runs it as an Argo CD `PostSync` smoke Job. The Job has no service
account token, no permitted network traffic, a read-only root filesystem,
dropped capabilities, bounded resources, and an in-memory temporary directory.

For Docker Desktop Kubernetes validation, build the application source commit
once and load that exact immutable tag without a registry round trip. The local
overlay currently records source revision `a3d44e128916`; update the overlay and
this command together when intentionally promoting another source revision:

```powershell
$sha = "a3d44e128916"
docker build --tag "readtheplan:sha-$sha" .
D:\Coding\devsecops-lab\tools\kind\v0.32.0\kind.exe load docker-image `
  "readtheplan:sha-$sha" --name desktop
kubectl apply -k deploy/kustomize/overlays/local
```

For shared environments, replace the local overlay image with the registry
reference already built, scanned, signed, and published by the release workflow.
Use an immutable `newName` plus `digest: sha256:<64-hex>` entry; never rebuild
during promotion. Argo CD should track the Git commit containing only that digest
change. The local workload uses `imagePullPolicy: Never`: a missing preloaded
image is a hard failure rather than an accidental registry pull. The tag is
derived from the source revision and is never reused for different bytes.

