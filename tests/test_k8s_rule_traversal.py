from __future__ import annotations

import readtheplan.rules.k8s as k8s_rules


def _deep_first_alias(shared: dict) -> dict:
    value = shared
    for _ in range(k8s_rules._MAX_K8S_TRAVERSAL_DEPTH - 1):
        value = {"child": value}
    return {"deep": value, "shallow": shared}


def test_tekton_secret_detection_revisits_alias_reached_shallower() -> None:
    shared = {"child": {"secretKeyRef": {"name": "build-token"}}}

    assert k8s_rules._tekton_has_secret_reference(_deep_first_alias(shared)) is True


def test_controller_key_detection_revisits_alias_reached_shallower() -> None:
    shared = {"child": {"secretKeyRef": {"name": "build-token"}}}

    assert (
        k8s_rules._controller_has_key(
            _deep_first_alias(shared),
            "secretKeyRef",
        )
        is True
    )


def test_rule_walkers_stop_on_recursive_object_graphs() -> None:
    recursive_mapping = {}
    recursive_mapping["nested"] = recursive_mapping
    recursive_list = []
    recursive_list.append(recursive_list)

    for recursive in (recursive_mapping, recursive_list):
        walked = list(k8s_rules._walk_k8s_value(recursive))
        assert len(walked) == 1
        assert walked[0] is recursive
        assert k8s_rules._tekton_has_secret_reference(recursive) is False
        assert k8s_rules._controller_has_key(recursive, "serviceAccountName") is False


def test_rule_walker_visits_ordinary_alias_dag_once() -> None:
    shared = {"leaf": "value"}
    value = {"first": shared, "second": shared}

    walked = list(k8s_rules._walk_k8s_value(value))

    assert sum(item is shared for item in walked) == 1


def test_rule_walker_stops_at_depth_budget() -> None:
    value = {}
    for _ in range(1_500):
        value = {"child": value}

    walked = list(k8s_rules._walk_k8s_value(value))

    assert len(walked) == k8s_rules._MAX_K8S_TRAVERSAL_DEPTH + 1


def test_tekton_privilege_detection_does_not_stringify_deep_mappings() -> None:
    value = "ordinary-value"
    for _ in range(1_500):
        value = {"child": value}

    assert k8s_rules._tekton_has_privileged_pod_settings(value) is False
