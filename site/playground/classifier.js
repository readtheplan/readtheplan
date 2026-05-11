// readtheplan playground classifier — pure JS port of rules engine
// v0: action-based baseline + top AWS resource types + compliance matching

const RISK_ORDER = { safe: 0, review: 1, dangerous: 2, irreversible: 3 };

// ── Baseline classification from action tuples ────────────────────────

function baselineRisk(actions) {
  const s = new Set(actions);
  if (s.has("delete") && s.has("create")) return "dangerous";
  if (s.has("delete")) return "irreversible";
  if (s.has("update")) return "review";
  if (isSubset(s, ["no-op", "read"])) return "safe";
  if (s.has("create")) return "safe";
  return "review"; // unknown → review
}

function baselineExplanation(actions) {
  const s = new Set(actions);
  if (s.has("delete") && s.has("create"))
    return "Terraform will replace this resource. Review downtime, identity changes, and state migration.";
  if (s.has("delete"))
    return "Terraform will delete this resource. Verify backups and dependencies.";
  if (s.has("update"))
    return "Terraform will update this resource in place. Review changed attributes.";
  if (isSubset(s, ["no-op", "read"]))
    return "Terraform is only reading or refreshing this resource.";
  if (s.has("create"))
    return "Terraform will create a new resource without changing existing state.";
  return "Action metadata is missing or unknown; human review required.";
}

// ── Helpers ─────────────────────────────────────────────────────────────

function isSubset(a, b) {
  for (const v of a) if (!b.includes(v)) return false;
  return true;
}

function maxRisk(a, b) {
  return RISK_ORDER[a] >= RISK_ORDER[b] ? a : b;
}

function maxRiskResult(r1, r2) {
  if (!r1) return r2;
  if (!r2) return r1;
  return RISK_ORDER[r2.risk] > RISK_ORDER[r1.risk] ? r2 : r1;
}

function beforeValue(change, key) {
  return change?.before?.[key] ?? change?.after?.[key];
}

function majorVersionChanged(change, key) {
  const a = String(change?.before?.[key] || "");
  const b = String(change?.after?.[key] || "");
  if (!a || !b || a === b) return false;
  return a.split(".")[0] !== b.split(".")[0];
}

// ── Resource-specific rules ────────────────────────────────────────────

function rdsRules(type, actions, change) {
  const label = type === "aws_rds_cluster" ? "RDS cluster" : "RDS instance";
  const results = [];

  if (actions.includes("delete") && actions.includes("create")) {
    results.push({ risk: "dangerous", explanation: `Terraform will replace this ${label}. Confirm snapshots, restore path, and endpoint changes.` });
  } else if (actions.includes("delete")) {
    results.push({ risk: "irreversible", explanation: `Terraform will delete this ${label}. Without a verified snapshot, data may be lost.` });
  } else if (actions.includes("update")) {
    results.push({ risk: "review", explanation: `Terraform will update this ${label}. Check backup state and maintenance windows.` });
  }

  if (majorVersionChanged(change, "engine_version")) {
    results.push({ risk: "dangerous", explanation: `${label} engine_version crosses a major version. May be irreversible or require downtime.` });
  }
  return results;
}

function s3Rules(type, actions, change) {
  const results = [];
  const forceDestroy = !!beforeValue(change, "force_destroy");

  if (actions.includes("delete")) {
    if (forceDestroy) {
      results.push({ risk: "irreversible", explanation: "S3 bucket with force_destroy enabled. Objects will be removed, recovery unlikely." });
    } else {
      results.push({ risk: "irreversible", explanation: "Terraform will delete S3 bucket. Confirm object retention and recovery requirements." });
    }
  } else if (actions.includes("update")) {
    results.push({ risk: "review", explanation: "Terraform will update S3 bucket controls. Review public access, encryption, and data exposure." });
  } else if (actions.includes("create")) {
    results.push({ risk: "safe", explanation: "Terraform will create S3 bucket. Confirm public access blocks before storing sensitive data." });
  }
  return results;
}

function kmsRules(actions) {
  if (actions.includes("delete") && actions.includes("create")) {
    return [{ risk: "dangerous", explanation: "KMS key replacement. Data encrypted with old key becomes inaccessible unless key material is preserved." }];
  }
  if (actions.includes("delete")) {
    return [{ risk: "irreversible", explanation: "KMS key scheduled for deletion. After the waiting period, all data under this key is permanently lost." }];
  }
  if (actions.includes("create")) {
    return [{ risk: "safe", explanation: "New KMS key creation. Isolated from existing keys." }];
  }
  return [];
}

function iamRules(type, actions, change) {
  const results = [];
  if (actions.includes("delete")) {
    results.push({ risk: "dangerous", explanation: `IAM ${type === "aws_iam_role" ? "role" : "policy"} will be deleted. Services relying on this may lose access.` });
  } else if (actions.includes("update") || actions.includes("create")) {
    results.push({ risk: "review", explanation: `IAM ${type === "aws_iam_role" ? "role" : "policy"} changed. Review permission boundaries and trust policy.` });
  }
  return results;
}

function lambdaRules(type, actions, change) {
  const results = [];
  if (actions.includes("delete")) {
    results.push({ risk: "dangerous", explanation: `Lambda ${type.includes("alias") ? "alias" : "function"} will be deleted. Verify no active invocations depend on it.` });
  } else if (actions.includes("update")) {
    results.push({ risk: "review", explanation: "Lambda function updated. Review runtime, handler, timeout, and memory changes." });
  }
  return results;
}

function route53Rules(actions) {
  if (actions.includes("delete")) {
    return [{ risk: "irreversible", explanation: "Route53 zone deletion. DNS records will be permanently removed. Verify domain ownership and migration plan." }];
  }
  return [];
}

function eksRules(actions) {
  if (actions.includes("delete")) {
    return [{ risk: "dangerous", explanation: "EKS node group will be deleted. Pods on these nodes will be evicted." }];
  }
  if (actions.includes("update")) {
    return [{ risk: "review", explanation: "EKS node group update. Review AMI, instance type, and scaling config changes." }];
  }
  return [];
}

function lbRules(type, actions) {
  if (actions.includes("delete")) {
    return [{ risk: "dangerous", explanation: `Load balancer ${type} will be deleted. Verify traffic is routed elsewhere.` }];
  }
  return [];
}

function networkRules(type, actions) {
  if (actions.includes("delete")) {
    if (type === "aws_nat_gateway") {
      return [{ risk: "dangerous", explanation: "NAT gateway deletion. Private subnets will lose internet access." }];
    }
    if (type === "aws_internet_gateway") {
      return [{ risk: "dangerous", explanation: "Internet gateway deletion. Public subnets will lose internet access." }];
    }
    return [{ risk: "review", explanation: `Network resource ${type} will be deleted. Verify routing tables and dependencies.` }];
  }
  return [];
}

function observabilityRules(type, actions) {
  if (actions.includes("delete")) {
    if (type === "aws_cloudwatch_metric_alarm") {
      return [{ risk: "review", explanation: "CloudWatch alarm deleted. Alerting gap until replacement is deployed." }];
    }
    if (type === "aws_cloudwatch_log_group") {
      return [{ risk: "review", explanation: "CloudWatch log group deleted. Logs will be permanently removed." }];
    }
  }
  return [];
}

// ── Main classifier ────────────────────────────────────────────────────

function classifyChange(resourceType, actions, change) {
  const baseline = {
    risk: baselineRisk(actions),
    explanation: baselineExplanation(actions),
  };

  let result = baseline;

  // Route to resource-specific rules
  let candidates = [];
  const rt = resourceType || "";

  if (["aws_db_instance", "aws_rds_cluster"].includes(rt)) {
    candidates = rdsRules(rt, actions, change);
  } else if (["aws_s3_bucket", "aws_s3_bucket_acl", "aws_s3_bucket_policy"].includes(rt)) {
    candidates = s3Rules(rt, actions, change);
  } else if (rt === "aws_kms_key") {
    candidates = kmsRules(actions);
  } else if (["aws_iam_role", "aws_iam_policy", "aws_iam_role_policy"].includes(rt)) {
    candidates = iamRules(rt, actions, change);
  } else if (["aws_lambda_function", "aws_lambda_alias", "aws_lambda_event_source_mapping"].includes(rt)) {
    candidates = lambdaRules(rt, actions, change);
  } else if (rt === "aws_route53_zone") {
    candidates = route53Rules(actions);
  } else if (rt === "aws_eks_node_group") {
    candidates = eksRules(actions);
  } else if (["aws_lb", "aws_lb_listener", "aws_lb_listener_rule", "aws_lb_target_group"].includes(rt)) {
    candidates = lbRules(rt, actions);
  } else if (["aws_subnet", "aws_route_table", "aws_route", "aws_nat_gateway", "aws_internet_gateway"].includes(rt)) {
    candidates = networkRules(rt, actions);
  } else if (["aws_cloudwatch_metric_alarm", "aws_cloudwatch_event_rule", "aws_cloudwatch_log_group"].includes(rt)) {
    candidates = observabilityRules(rt, actions);
  }

  for (const c of candidates) {
    result = maxRiskResult(result, c);
  }

  return result;
}

// ── Plan parsing ───────────────────────────────────────────────────────

function parsePlan(json) {
  const changes = [];
  const resourceChanges = json?.resource_changes || [];

  for (const rc of resourceChanges) {
    const actions = rc?.change?.actions || ["no-op"];
    const type = rc?.type || "unknown";
    const name = rc?.name || rc?.address || "unknown";
    const change = rc?.change || {};

    const classification = classifyChange(type, actions, change);

    changes.push({
      address: name,
      type: type,
      actions: actions,
      risk: classification.risk,
      explanation: classification.explanation,
      before: change.before || {},
      after: change.after || {},
    });
  }

  return changes;
}

// ── Compliance matching ────────────────────────────────────────────────

function matchCompliance(changes, framework, complianceData) {
  const catalog = complianceData?.[framework];
  if (!catalog) return changes;

  for (const change of changes) {
    change.controls = [];
    for (const mapping of catalog.mappings || []) {
      if (mapping.resource_type === change.type) {
        const hasAction = mapping.actions.some(a => change.actions.includes(a));
        if (hasAction || mapping.actions.includes("*")) {
          for (const ctrl of mapping.controls || []) {
            change.controls.push({ id: ctrl.id, title: ctrl.title });
          }
        }
      }
    }
  }

  return changes;
}

// ── Risk summary ───────────────────────────────────────────────────────

function summarize(changes) {
  const counts = { safe: 0, review: 0, dangerous: 0, irreversible: 0 };
  let highest = "safe";
  for (const c of changes) {
    counts[c.risk] = (counts[c.risk] || 0) + 1;
    if (RISK_ORDER[c.risk] > RISK_ORDER[highest]) highest = c.risk;
  }
  return { counts, highest, total: changes.length };
}

// ── Export ─────────────────────────────────────────────────────────────

if (typeof module !== "undefined" && module.exports) {
  module.exports = { parsePlan, matchCompliance, summarize, classifyChange, baselineRisk };
}
