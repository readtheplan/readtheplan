# GitOps smoke job

`readtheplan` is a one-shot CLI, not a network service. This Kustomize package
therefore runs it as an Argo CD `PostSync` smoke Job. The Job has no service
account token, no permitted network traffic, a read-only root filesystem,
dropped capabilities, bounded resources, and an in-memory temporary directory.
The successful Job and logs remain available as the latest execution evidence;
`BeforeHookCreation` replaces them only when a later sync creates the next
smoke Job.

For Docker Desktop Kubernetes validation, build the application source commit
once, publish it to the local Nexus hosted Docker repository, sign the returned
digest with Cosign, and promote only that digest. The local overlay currently
records digest
`sha256:e3af427b90d73f7116ab125dfb1c60a7a15ebc588a924910d96a7d0d766afd25`:

```powershell
$sha = "a3d44e128916"
docker build --tag "readtheplan:sha-$sha" .
docker tag "readtheplan:sha-$sha" `
  "nexus.devsecops.internal/docker-hosted/readtheplan:sha-$sha"
docker push "nexus.devsecops.internal/docker-hosted/readtheplan:sha-$sha"
kubectl apply -k deploy/kustomize/overlays/local
```

The `nexus-registry` image pull secret is cluster bootstrap state and is not
committed. Sigstore policy-controller validates the colocated Cosign signature
using the Pod's pull secret before the Job is admitted. Use an immutable
`newName` plus `digest: sha256:<64-hex>` entry in every environment; never rebuild
during promotion. Argo CD should track the Git commit containing only that digest
change. The human-readable tag is derived from the source revision and is never
reused for different bytes.
