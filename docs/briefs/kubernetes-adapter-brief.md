# Kubernetes adapter for readtheplan agent-gate

## Goal
Add a `KubernetesAdapter` following the existing `CloudFormationAdapter` pattern, accepting rendered K8s YAML diff JSON and normalizing to the shared agent-gate contract.

## Files to create
1. `src/readtheplan/adapters/kubernetes.py` — Kubernetes adapter class
2. `tests/test_k8s_adapter.py` — adapter tests with fixture manifests

## Files to modify
3. `src/readtheplan/adapters/__init__.py` — register and export new adapter
4. `src/readtheplan/cli.py` — support `--framework kubernetes` in agent-gate
5. `src/readtheplan/mcp_server.py` — add `agent_gate_kubernetes` MCP tool

## Acceptance criteria
1. `KubernetesAdapter` implements all 4 abstract methods: `adapter_name`, `can_handle`, `extract_changes`, `normalize_change`
2. `can_handle` detects JSON with `"old_manifests"` / `"new_manifests"` keys OR a `"resources"` array with `kind` fields
3. `extract_changes` compares old vs new manifests by resource identity (kind + name + namespace) and produces change dicts with Action, Kind, ResourceType, Namespace, logical_id, and `_metadata` for rules engine
4. `normalize_change` maps K8s `kind` to normalized types matching `rules/k8s.py` (`kubernetes_deployment`, `kubernetes_service`, `kubernetes_ingress`, `kubernetes_secret`, `kubernetes_config_map`, `kubernetes_namespace`, `kubernetes_cluster_role`, `kubernetes_cluster_role_binding`, `kubernetes_role_binding`, `kubernetes_network_policy`, `kubernetes_persistent_volume_claim`)
5. Risk mapping: Create=safe, Delete=irreversible, Replace=delete+create=dangerous, Update=review (with `_metadata` containing `before`/`after` for rules engine)
6. Top-level `analyze_kubernetes(data)` function that uses the adapter and returns agent-gate dict (same shape as `analyze_cloudformation`)
7. Registered in `__init__.py` and auto-discovered
8. CLI: `readtheplan agent-gate --framework kubernetes <file.json>` works
9. MCP tool `agent_gate_kubernetes(input_path)` works
10. Tests include:
    - Deployment create/safe
    - Deployment modify/review with metadata
    - Deployment delete/irreversible
    - Service type change (ClusterIP→NodePort)/review
    - Secret create/dangerous
    - RBAC delete/irreversible
    - Namespace replacement/dangerous
    - Empty input (no changes)
    - Single-manifest pass-through (just a resource array, no old/new)

## Implementation notes
- Follow `cloudformation.py` structure exactly — copy the `_TYPE_MAP` pattern but for K8s kinds
- K8s resource matching: match by `(Kind, name, namespace)` across old/new arrays
- For single-manifest input (no old/new comparison), default to "create" actions
- Reuse `rules/k8s.py` via the shared `_apply_resource_rules` from `BaseAdapter`
- Input JSON format:
  ```json
  {
    "old_manifests": [{"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "web", "namespace": "default"}, "spec": {...}}],
    "new_manifests": [{"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "web", "namespace": "default"}, "spec": {...}}]
  }
  ```
  or
  ```json
  {
    "resources": [{"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "web"}, "spec": {...}}]
  }
  ```

## Pitfalls
- K8s kinds are PascalCase — map to lowercase with `kubernetes_` prefix: `Deployment` → `kubernetes_deployment`
- Namespace matters for identity — resources without namespace default to `"default"`
- Cluster-scoped resources (ClusterRole, Namespace, etc.) have no namespace
- RBAC resources: `Role` → `kubernetes_role`, `ClusterRole` → `kubernetes_cluster_role`
- The `_metadata` dict must use `before`/`after` keys matching `rules/_shared.py` expectations
- Resource matching across manifests needs to handle renames (if metadata.name changed, it's a delete+create)
- Not all fields are meaningful for comparison — focus on spec, metadata.labels, metadata.annotations, data (ConfigMap/Secret)
