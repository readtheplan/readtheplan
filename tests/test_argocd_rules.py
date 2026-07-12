from __future__ import annotations

from readtheplan.adapters.kubernetes import KubernetesAdapter, parse_kubernetes_input


def _analyze(source: str):
    data = parse_kubernetes_input(source)
    return KubernetesAdapter().analyze(data, tool_name="Kubernetes")[0]


def test_application_with_automated_prune_is_dangerous() -> None:
    change = _analyze(
        """\
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: production
  namespace: argocd
spec:
  project: default
  source:
    repoURL: https://github.com/example/platform.git
    targetRevision: main
    path: clusters/production
  destination:
    server: https://kubernetes.default.svc
    namespace: production
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
"""
    )
    assert change.resource_type == "kubernetes_argocd_application"
    assert change.risk == "dangerous"
    assert "automated pruning" in change.explanation


def test_disabled_automation_does_not_escalate_prune() -> None:
    change = _analyze(
        """\
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: staging
spec:
  syncPolicy:
    automated:
      enabled: false
      prune: true
"""
    )
    assert change.risk == "review"
    assert "source repository" in change.explanation


def test_appproject_wildcard_boundaries_are_dangerous() -> None:
    change = _analyze(
        """\
apiVersion: argoproj.io/v1alpha1
kind: AppProject
metadata:
  name: unrestricted
  namespace: argocd
spec:
  sourceRepos: ['*']
  destinations:
    - server: '*'
      namespace: '*'
  clusterResourceWhitelist:
    - group: '*'
      kind: '*'
  roles:
    - name: admin
      policies:
        - p, proj:unrestricted:admin, applications, *, unrestricted/*, allow
"""
    )
    assert change.resource_type == "kubernetes_argocd_project"
    assert change.risk == "dangerous"
    assert "wildcard scope" in change.explanation
    assert "destinations" in change.explanation
    assert "source repositories" in change.explanation


def test_scoped_appproject_requires_review() -> None:
    change = _analyze(
        """\
apiVersion: argoproj.io/v1alpha1
kind: AppProject
metadata:
  name: payments
spec:
  sourceRepos:
    - https://github.com/example/payments.git
  destinations:
    - server: https://kubernetes.default.svc
      namespace: payments
"""
    )
    assert change.risk == "review"
    assert "allowed sources" in change.explanation


def test_applicationset_pruning_is_dangerous() -> None:
    change = _analyze(
        """\
apiVersion: argoproj.io/v1alpha1
kind: ApplicationSet
metadata:
  name: clusters
spec:
  generators:
    - clusters: {}
  template:
    metadata:
      name: '{{name}}'
    spec:
      project: default
      syncPolicy:
        automated:
          prune: true
"""
    )
    assert change.resource_type == "kubernetes_argocd_application_set"
    assert change.risk == "dangerous"
    assert "multiple generated Applications" in change.explanation


def test_application_kind_from_other_api_group_stays_generic() -> None:
    change = _analyze(
        """\
apiVersion: example.io/v1
kind: Application
metadata:
  name: example
spec: {}
"""
    )
    assert change.resource_type == "kubernetes_application"
    assert change.risk == "review"
