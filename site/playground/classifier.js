// readtheplan playground classifier — pure JS port of rules engine
// v1: fully aligned with src/readtheplan/rules.py (parity pass 2026-06-02)

const RISK_ORDER = { safe: 0, review: 1, dangerous: 2, irreversible: 3 };

const KNOWN_ACTIONS = new Set(["no-op", "read", "create", "update", "delete"]);

// ── Baseline classification from action tuples ────────────────────────

function baselineRisk(actions) {
  if (!actions || actions.length === 0) return "review";
  const s = new Set(actions);
  if (s.has("delete") && s.has("create")) return "dangerous";
  if (s.has("delete")) return "irreversible";
  if (s.has("update")) return "review";
  if (isSubset(s, ["no-op", "read"])) return "safe";
  // Only allow "create" to produce "safe" when all actions are known.
  // Unknown/malformed actions must be "review" (ADR 0003).
  if (s.has("create") && isSubsetOfKnown(s)) return "safe";
  return "review";
}

function baselineExplanation(actions) {
  const s = new Set(actions);
  if (!actions || actions.length === 0)
    return "Terraform action metadata is missing or unknown; human review is required.";
  if (s.has("delete") && s.has("create"))
    return "Terraform will replace this resource. Review downtime, identity changes, and any state that must be migrated or restored.";
  if (s.has("delete"))
    return "Terraform will delete this resource. Verify recovery, backups, and external dependencies before applying.";
  if (s.has("update"))
    return "Terraform will update this resource in place. Review the changed attributes and rollout timing before applying.";
  if (isSubset(s, ["no-op", "read"]))
    return "Terraform is only reading or refreshing this resource.";
  if (s.has("create") && isSubsetOfKnown(s))
    return "Terraform will create a new resource without changing existing state.";
  return "Terraform action metadata is missing or unknown; human review is required.";
}

// ── Helpers ─────────────────────────────────────────────────────────────

function isSubset(a, b) {
  for (const v of a) if (!b.includes(v)) return false;
  return true;
}

function isSubsetOfKnown(s) {
  for (const v of s) if (!KNOWN_ACTIONS.has(v)) return false;
  return true;
}

function maxRisk(a, b) {
  return RISK_ORDER[a] >= RISK_ORDER[b] ? a : b;
}

function maxRiskResult(r1, r2) {
  if (!r1) return r2;
  if (!r2) return r1;
  return RISK_ORDER[r2.risk] >= RISK_ORDER[r1.risk] ? r2 : r1;
}

// _before_value: returns None if before is not a dict (no fallback to after)
function beforeValue(change, key) {
  const before = change?.before;
  if (before && typeof before === "object" && !Array.isArray(before)) {
    return before[key];
  }
  return undefined;
}

// _after_value: returns None if after is not a dict
function afterValue(change, key) {
  const after = change?.after;
  if (after && typeof after === "object" && !Array.isArray(after)) {
    return after[key];
  }
  return undefined;
}

// _attribute_changed: both before and after must be dicts, and values differ
function attributeChanged(change, key) {
  const before = change?.before;
  const after = change?.after;
  if (!before || typeof before !== "object" || Array.isArray(before)) return false;
  if (!after || typeof after !== "object" || Array.isArray(after)) return false;
  return !deepEqual(before[key], after[key]);
}

function deepEqual(a, b) {
  if (a === b) return true;
  if (typeof a !== typeof b) return false;
  if (a === null || b === null) return a === b;
  if (typeof a === "object") {
    try { return JSON.stringify(a) === JSON.stringify(b); }
    catch (_) { return false; }
  }
  return false;
}

// _major_version_changed: major version digits differ
function majorVersionChanged(change, key) {
  if (!attributeChanged(change, key)) return false;
  const bv = majorVersionNum(beforeValue(change, key));
  const av = majorVersionNum(afterValue(change, key));
  return bv !== null && av !== null && bv !== av;
}

function majorVersionNum(value) {
  if (value === null || value === undefined) return null;
  const match = String(value).match(/^\s*(\d+)/);
  return match ? parseInt(match[1], 10) : null;
}

// _runtime_major_changed: extract runtime prefix+number and compare
function runtimeMajorChanged(change) {
  if (!attributeChanged(change, "runtime")) return false;
  const bv = beforeValue(change, "runtime");
  const av = afterValue(change, "runtime");
  if (typeof bv !== "string" || typeof av !== "string") return false;
  const bm = extractRuntimeMajor(bv);
  const am = extractRuntimeMajor(av);
  return bm !== null && am !== null && bm !== am;
}

function extractRuntimeMajor(runtime) {
  const match = String(runtime).match(/^([a-zA-Z]+)(\d+)/);
  return match ? match[1] + match[2] : null;
}

// AWS Lambda runtimes deprecated as of 2026-05.
const DEPRECATED_RUNTIMES = new Set([
  "nodejs12.x", "nodejs14.x", "nodejs16.x",
  "python3.6", "python3.7", "python3.8",
  "dotnetcore3.1", "dotnet5.0", "dotnet6",
  "ruby2.5", "ruby2.7",
  "java8", "java8.al2",
  "go1.x", "provided",
]);

function runtimeDeprecated(change) {
  const av = afterValue(change, "runtime");
  if (typeof av === "string" && DEPRECATED_RUNTIMES.has(av)) return true;
  const bv = beforeValue(change, "runtime");
  if (typeof bv === "string" && DEPRECATED_RUNTIMES.has(bv)) return true;
  return false;
}

function healthCheckChanged(change) {
  const before = change?.before;
  const after = change?.after;
  if (!before || typeof before !== "object" || !after || typeof after !== "object") return false;
  const bh = before.health_check;
  const ah = after.health_check;
  return bh !== ah && bh != null && ah != null;
}

function retentionDecreased(change, key) {
  if (!attributeChanged(change, key)) return false;
  const bv = beforeValue(change, key);
  const av = afterValue(change, key);
  if (typeof bv !== "number" || typeof av !== "number") return false;
  return av < bv;
}

// ── Policy/security helpers ─────────────────────────────────────────────

function policyDocument(value) {
  if (value && typeof value === "object" && !Array.isArray(value)) return value;
  if (typeof value === "string") {
    try {
      const decoded = JSON.parse(value);
      if (decoded && typeof decoded === "object" && !Array.isArray(decoded)) return decoded;
    } catch (_) { /* invalid JSON */ }
  }
  return null;
}

function policyAllowsPublic(policy) {
  if (!policy) return false;
  const stmts = statements(policy);
  for (const s of stmts) {
    if (statementEffect(s) === "allow" && principalIsPublic(s)) return true;
  }
  return false;
}

function hasDenyStatement(policy) {
  if (!policy) return false;
  const stmts = statements(policy);
  for (const s of stmts) {
    if (statementEffect(s) === "deny") return true;
  }
  return false;
}

function statements(policy) {
  const stmts = policy.Statement || [];
  if (stmts && typeof stmts === "object" && !Array.isArray(stmts)) return [stmts];
  if (!Array.isArray(stmts)) return [];
  return stmts.filter(s => s && typeof s === "object");
}

function statementEffect(statement) {
  return String(statement.Effect || "").toLowerCase();
}

function principalIsPublic(statement) {
  const principal = statement.Principal;
  if (principal === "*") return true;
  if (principal && typeof principal === "object" && !Array.isArray(principal)) {
    for (const key of Object.keys(principal)) {
      if (containsPublicPrincipal(principal[key])) return true;
    }
  }
  return false;
}

function containsPublicPrincipal(value) {
  if (value === "*") return true;
  if (Array.isArray(value)) {
    for (const item of value) if (item === "*") return true;
  }
  return false;
}

// ── Security / route validation ────────────────────────────────────────

function s3PublicExposure(resourceType, change) {
  const acl = afterValue(change, "acl");
  if (typeof acl === "string" && ["public-read", "public-read-write"].includes(acl.toLowerCase())) {
    return true;
  }
  if (resourceType === "aws_s3_bucket_policy" || afterValue(change, "policy")) {
    const policy = policyDocument(afterValue(change, "policy"));
    return policy !== null && policyAllowsPublic(policy);
  }
  return false;
}

function securityGroupOpensToInternet(resourceType, change) {
  if (resourceType === "aws_security_group") {
    const ingress = afterValue(change, "ingress");
    if (Array.isArray(ingress)) {
      return ingress.some(rule => ruleBlockOpensToInternet(rule));
    }
    return ruleBlockOpensToInternet(ingress);
  }
  return ruleBlockOpensToInternet(change?.after);
}

function ruleBlockOpensToInternet(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;

  const v4 = value.cidr_blocks;
  if (Array.isArray(v4) && v4.some(c => c === "0.0.0.0/0")) return true;

  const v6 = value.ipv6_cidr_blocks;
  if (Array.isArray(v6) && v6.some(c => c === "::/0")) return true;

  if (value.cidr_ipv4 === "0.0.0.0/0" || value.cidr_ipv6 === "::/0") return true;

  const nested = value.ingress;
  if (Array.isArray(nested) && nested.some(rule => ruleBlockOpensToInternet(rule))) return true;

  return false;
}

function routeOpensInternetPath(change) {
  const dest = afterValue(change, "destination_cidr_block");
  const dest6 = afterValue(change, "destination_ipv6_cidr_block");
  const gwId = afterValue(change, "gateway_id");
  return (
    (dest === "0.0.0.0/0" || dest6 === "::/0") &&
    typeof gwId === "string" &&
    (gwId.startsWith("igw-") || gwId.includes("internet_gateway"))
  );
}

// ── Resource-specific rules ────────────────────────────────────────────

// RDS
function rdsRules(type, actions, change) {
  const label = type === "aws_rds_cluster" ? "RDS cluster" : "RDS instance";
  const s = new Set(actions);
  const results = [];

  if (s.has("create") && s.has("delete")) {
    results.push({ risk: "dangerous", explanation: `Terraform will replace this ${label}. Confirm snapshots, restore path, endpoint changes, and maintenance-window impact.` });
  } else if (s.has("delete")) {
    results.push({ risk: "irreversible", explanation: `Terraform will delete this ${label}. Without a verified final snapshot or restore plan, database data may be lost.` });
  } else if (s.has("update")) {
    results.push({ risk: "review", explanation: `Terraform will update this ${label}. Check backup state, maintenance windows, and whether the provider will force replacement.` });
  }

  if (majorVersionChanged(change, "engine_version")) {
    results.push({ risk: "dangerous", explanation: `The ${label} engine_version appears to cross a major version. Major database upgrades can be irreversible or require downtime.` });
  }
  return results;
}

// S3
function s3Rules(type, actions, change) {
  const s = new Set(actions);
  const results = [];
  const forceDestroy = !!beforeValue(change, "force_destroy");

  if (s.has("delete")) {
    if (forceDestroy) {
      results.push({ risk: "irreversible", explanation: "Terraform will delete an S3 bucket with force_destroy enabled. Objects can be removed along with the bucket, making recovery unlikely." });
    } else {
      results.push({ risk: "irreversible", explanation: "Terraform will delete an S3 bucket or bucket control resource. Confirm object retention, replication, and recovery requirements." });
    }
  } else if (s.has("update")) {
    results.push({ risk: "review", explanation: "Terraform will update S3 bucket controls. Review public access, retention, encryption, and data exposure settings." });
  } else if (s.has("create")) {
    results.push({ risk: "safe", explanation: "Terraform will create S3 bucket infrastructure. Confirm public access blocks and data classification before storing sensitive data." });
  }

  if (s3PublicExposure(type, change)) {
    results.push({ risk: "dangerous", explanation: "This S3 change appears to allow public access through an ACL or bucket policy. Public data exposure requires security review." });
  }
  return results;
}

// KMS
function kmsRules(actions) {
  const s = new Set(actions);
  if (s.has("create") && s.has("delete")) {
    return [{ risk: "dangerous", explanation: "Terraform will replace a KMS key. Key identity changes can break decrypt access for data and services that depend on the old key." }];
  }
  if (s.has("delete")) {
    return [{ risk: "irreversible", explanation: "Terraform will schedule deletion of a KMS key. Once the deletion window completes, data encrypted only by that key cannot be decrypted." }];
  }
  if (s.has("update")) {
    return [{ risk: "review", explanation: "Terraform will update a KMS key. Review key policy, rotation, deletion window, and service dependencies." }];
  }
  return [];
}

// IAM
function iamRules(type, actions, change) {
  const s = new Set(actions);
  const results = [];

  if (s.has("delete")) {
    results.push({ risk: "irreversible", explanation: "Terraform will delete IAM authorization infrastructure. Confirm no workloads, humans, or break-glass paths depend on it." });
  } else if (s.has("update")) {
    results.push({ risk: "review", explanation: "Terraform will update IAM authorization. Review trust policies, permission boundaries, and deny statements for lockout or escalation risk." });
  }

  if (type === "aws_iam_role" && attributeChanged(change, "assume_role_policy")) {
    results.push({ risk: "dangerous", explanation: "The IAM role trust policy is changing. A bad assume_role_policy can lock out workloads or allow unintended principals to assume the role." });
  }

  const policyAttr = type === "aws_iam_role" ? "assume_role_policy" : "policy";
  const beforePolicy = policyDocument(beforeValue(change, policyAttr));
  const afterPolicy = policyDocument(afterValue(change, policyAttr));
  if (beforePolicy !== null && afterPolicy !== null) {
    if (hasDenyStatement(beforePolicy) && !hasDenyStatement(afterPolicy)) {
      results.push({ risk: "dangerous", explanation: "This IAM policy change appears to remove deny statements. Removing explicit denies can widen access even when allow rules look unchanged." });
    }
  }

  return results;
}

// Route53
function route53Rules(actions) {
  const s = new Set(actions);
  if (s.has("create") && s.has("delete")) {
    return [{ risk: "dangerous", explanation: "Terraform will replace a Route53 hosted zone. Name server changes can take production DNS offline until delegations and records are repaired." }];
  }
  if (s.has("delete")) {
    return [{ risk: "irreversible", explanation: "Terraform will delete a Route53 hosted zone. DNS for the zone can go dark, and recreating it may produce different name servers." }];
  }
  if (s.has("update")) {
    return [{ risk: "review", explanation: "Terraform will update a Route53 hosted zone. Review delegation, record ownership, and downstream DNS dependencies." }];
  }
  return [];
}

// EKS node group
function eksNodeGroupRules(actions) {
  const s = new Set(actions);
  if (s.has("create") && s.has("delete")) {
    return [{ risk: "dangerous", explanation: "Terraform will replace an EKS node group. Expect pod evictions, capacity churn, and possible cluster disruption during rollout." }];
  }
  if (s.has("delete")) {
    return [{ risk: "irreversible", explanation: "Terraform will delete an EKS node group. Confirm replacement capacity and disruption budgets before applying." }];
  }
  if (s.has("update")) {
    return [{ risk: "review", explanation: "Terraform will update an EKS node group. Review rollout settings, surge capacity, labels, taints, and workload disruption budgets." }];
  }
  return [];
}

// ECS service
function ecsServiceRules(actions, change) {
  const s = new Set(actions);
  if (s.has("create") && s.has("delete")) {
    return [{ risk: "dangerous", explanation: "Terraform will replace an ECS service. Expect running tasks to be drained, possible service disruption, and ALB re-registration delay." }];
  }
  if (s.has("delete")) {
    return [{ risk: "irreversible", explanation: "Terraform will delete an ECS service. All tasks, service discovery entries, and auto-scaling policies will be removed. Confirm that traffic has been routed away." }];
  }
  if (s.has("update")) {
    const results = [];
    if (attributeChanged(change, "force_new_deployment")) {
      results.push({ risk: "dangerous", explanation: "force_new_deployment is set on an ECS service update. All running tasks will be replaced, causing a rolling restart with potential service disruption." });
    }
    if (attributeChanged(change, "launch_type")) {
      results.push({ risk: "review", explanation: "ECS launch_type is changing (e.g. EC2 to FARGATE). Review capacity providers, networking mode, and task placement compatibility." });
    }
    if (results.length === 0) {
      results.push({ risk: "review", explanation: "Terraform will update an ECS service. Review deployment configuration, desired count, task definition, and health check grace period before applying." });
    }
    return results;
  }
  return [];
}

// Load Balancer
function lbRules(type, actions, change) {
  const s = new Set(actions);
  const results = [];

  if (type === "aws_lb") {
    if (s.has("delete") && s.has("create")) {
      results.push({ risk: "dangerous", explanation: "Terraform will replace this load balancer. Expect DNS rebinding, connection draining, and possible downtime for all fronted services." });
    } else if (s.has("delete")) {
      results.push({ risk: "irreversible", explanation: "Terraform will delete this load balancer. All listeners, target groups, and DNS aliases are affected immediately." });
    } else if (s.has("update")) {
      results.push({ risk: "review", explanation: "Terraform will update this load balancer. Review attribute changes for availability impact." });
    }
    if (attributeChanged(change, "internal")) {
      results.push({ risk: "irreversible", explanation: "The load balancer scheme is changing between internal and internet-facing. DNS and address rebinding is required; this is effectively irreversible without downtime." });
    }
  } else if (type === "aws_lb_listener") {
    if (s.has("delete")) {
      results.push({ risk: "dangerous", explanation: "Terraform will delete a load balancer listener. Production traffic on this port will be dropped." });
    }
    if (attributeChanged(change, "port") || attributeChanged(change, "protocol")) {
      results.push({ risk: "dangerous", explanation: "Load balancer listener port or protocol is changing. Clients may not reconnect to the new endpoint." });
    }
    if (attributeChanged(change, "default_action")) {
      results.push({ risk: "dangerous", explanation: "Load balancer listener default_action is changing. This fronts production traffic; a misroute is immediately visible." });
    }
  } else if (type === "aws_lb_listener_rule") {
    if (attributeChanged(change, "priority")) {
      results.push({ risk: "review", explanation: "Listener rule priority is changing. Routing precedence is sensitive and concurrent priority changes can race." });
    } else if (s.has("update")) {
      results.push({ risk: "review", explanation: "Terraform will update a listener rule. Review condition and action changes for routing impact." });
    }
  } else if (type === "aws_lb_target_group") {
    if (s.has("create") && s.has("delete")) {
      results.push({ risk: "dangerous", explanation: "Terraform will replace this target group. Target registrations are lost and must re-register, causing a traffic gap." });
    } else if (s.has("delete")) {
      results.push({ risk: "irreversible", explanation: "Terraform will delete this target group. Confirm no listeners still reference it and no traffic depends on it." });
    }
    if (attributeChanged(change, "target_type")) {
      results.push({ risk: "dangerous", explanation: "Target group target_type is changing. This forces replacement and disrupts all registered targets." });
    }
    if (healthCheckChanged(change)) {
      results.push({ risk: "review", explanation: "Target group health check settings are changing. Aggressive thresholds can mass-fail healthy targets." });
    }
  } else if (type === "aws_lb_target_group_attachment") {
    if (s.has("delete") && !s.has("create")) {
      results.push({ risk: "review", explanation: "Terraform will detach a target from a target group. Traffic will no longer route to this target." });
    }
  }

  return results;
}

// Lambda
function lambdaRules(type, actions, change) {
  const s = new Set(actions);
  const results = [];

  if (type !== "aws_lambda_function") return results;
  if (!s.has("update")) return results;

  if (attributeChanged(change, "package_type")) {
    results.push({ risk: "dangerous", explanation: "Lambda package_type is changing (e.g. zip to image). This switch is not always cleanly reversible and may require infrastructure changes." });
  }
  if (attributeChanged(change, "code_signing_config_arn")) {
    results.push({ risk: "review", explanation: "Lambda code_signing_config_arn is changing. Review that the new signing profile is trusted and deployment pipeline aligned." });
  }
  if (attributeChanged(change, "vpc_config")) {
    results.push({ risk: "review", explanation: "Lambda vpc_config is changing. Network attachment changes affect downstream connectivity and cold-start latency." });
  }
  if (runtimeMajorChanged(change)) {
    results.push({ risk: "review", explanation: "Lambda runtime major version is changing. Review compatibility of dependencies and runtime behavior." });
  }
  if (attributeChanged(change, "role")) {
    results.push({ risk: "review", explanation: "Lambda execution role is changing. The permission boundary may shift, affecting what the function can access." });
  }
  if (runtimeDeprecated(change)) {
    results.push({ risk: "dangerous", explanation: "Lambda runtime is deprecated or approaching end-of-life. AWS may block function updates or invocations for deprecated runtimes. Upgrade to a supported runtime before applying." });
  }

  return results;
}

// Platform services: ECR, SQS, Glue
function platformServiceRules(type, actions, change) {
  const s = new Set(actions);
  const results = [];

  if (type === "aws_ecr_repository") {
    if (s.has("delete") && s.has("create")) {
      results.push({ risk: "dangerous", explanation: "Terraform will replace an ECR repository. Image URLs, repository policy, scanning, and pull paths may change." });
    } else if (s.has("delete")) {
      results.push({ risk: "irreversible", explanation: "Terraform will delete an ECR repository. Container images and tags may be removed with the repository." });
    } else if (s.has("update")) {
      results.push({ risk: "review", explanation: "Terraform will update an ECR repository. Review image scanning, mutability, encryption, and lifecycle posture." });
    }
  } else if (type === "aws_ecr_repository_policy") {
    results.push(...policyResourceRules(actions, change, "ECR repository policy", "container images"));
  } else if (type === "aws_ecr_lifecycle_policy") {
    if (s.has("delete")) {
      results.push({ risk: "review", explanation: "Terraform will delete an ECR lifecycle policy. Old images may accumulate or retention assumptions may change." });
    } else if (s.has("update") || s.has("create")) {
      results.push({ risk: "review", explanation: "Terraform will change an ECR lifecycle policy. Confirm tag retention rules will not expire rollback images too early." });
    }
  } else if (type === "aws_sqs_queue") {
    if (s.has("delete") && s.has("create")) {
      results.push({ risk: "dangerous", explanation: "Terraform will replace an SQS queue. Queue URL/ARN changes can break producers, consumers, and dead-letter routing." });
    } else if (s.has("delete")) {
      results.push({ risk: "irreversible", explanation: "Terraform will delete an SQS queue. Undelivered messages and dead-letter history can be lost." });
    } else if (s.has("update")) {
      results.push({ risk: "review", explanation: "Terraform will update an SQS queue. Review retention, visibility timeout, encryption, and redrive policy changes." });
    }
    if (["redrive_policy", "visibility_timeout_seconds", "message_retention_seconds"].some(k => attributeChanged(change, k))) {
      results.push({ risk: "review", explanation: "SQS delivery semantics are changing. Redrive, visibility, or retention changes can cause retries, loss, or backlog growth." });
    }
  } else if (type === "aws_sqs_queue_policy") {
    results.push(...policyResourceRules(actions, change, "SQS queue policy", "queue producers and consumers"));
  } else if (type === "aws_glue_catalog_database" || type === "aws_glue_catalog_table") {
    const label = type === "aws_glue_catalog_database" ? "Glue catalog database" : "Glue catalog table";
    if (s.has("delete") && s.has("create")) {
      results.push({ risk: "dangerous", explanation: `Terraform will replace a ${label}. Data catalog identity changes can break analytics jobs and lineage references.` });
    } else if (s.has("delete")) {
      results.push({ risk: "dangerous", explanation: `Terraform will delete a ${label}. Queries and ETL jobs depending on the catalog entry may fail.` });
    } else if (s.has("update")) {
      results.push({ risk: "review", explanation: `Terraform will update a ${label}. Review schema, location, classification, and consumer compatibility.` });
    }
  } else if (type === "aws_glue_job") {
    if (s.has("delete") && s.has("create")) {
      results.push({ risk: "dangerous", explanation: "Terraform will replace a Glue job. Schedule bindings, bookmarks, permissions, and ETL behavior may change." });
    } else if (s.has("delete")) {
      results.push({ risk: "irreversible", explanation: "Terraform will delete a Glue job. Dependent data pipelines will stop running unless an equivalent job exists." });
    } else if (s.has("update")) {
      results.push({ risk: "review", explanation: "Terraform will update a Glue job. Review script, role, worker, bookmark, and connection changes before rollout." });
    }
    if (attributeChanged(change, "role_arn")) {
      results.push({ risk: "review", explanation: "Glue job role_arn is changing. The ETL job's data access boundary may shift." });
    }
  }

  return results;
}

function policyResourceRules(actions, change, label, protectedSubject) {
  const s = new Set(actions);
  const results = [];
  if (s.has("delete")) {
    results.push({ risk: "dangerous", explanation: `Terraform will delete a ${label}. Access for ${protectedSubject} may become too broad or too restrictive depending on defaults.` });
  } else if (s.has("update") || s.has("create")) {
    results.push({ risk: "review", explanation: `Terraform will change a ${label}. Review principals, actions, and cross-account access before applying.` });
  }

  const policy = policyDocument(afterValue(change, "policy"));
  if (policy !== null && policyAllowsPublic(policy)) {
    results.push({ risk: "dangerous", explanation: `This ${label} appears to allow public access. Public or anonymous access requires security review.` });
  }
  return results;
}

// Security groups
function securityGroupRules(type, actions, change) {
  const s = new Set(actions);
  const results = [];

  if (s.has("delete") && s.has("create")) {
    results.push({ risk: "dangerous", explanation: "Terraform will replace security group network boundaries. Attached workloads may lose expected traffic paths during rollout." });
  } else if (s.has("delete")) {
    results.push({ risk: "dangerous", explanation: "Terraform will delete security group configuration. Ingress/egress permissions for attached workloads may break." });
  } else if (s.has("update") || s.has("create")) {
    results.push({ risk: "review", explanation: "Terraform will change security group rules. Review ports, protocols, and source/destination boundaries before applying." });
  }

  if (securityGroupOpensToInternet(type, change)) {
    results.push({ risk: "dangerous", explanation: "This security group change appears to allow internet-wide access (0.0.0.0/0 or ::/0). Confirm this exposure is intentional." });
  }

  return results;
}

// Network topology
function networkTopologyRules(type, actions, change) {
  const s = new Set(actions);
  const results = [];

  if (type === "aws_subnet") {
    if (s.has("delete") && s.has("create")) {
      results.push({ risk: "dangerous", explanation: "Terraform will replace a subnet. ENIs, load balancers, NAT placement, and workload attachment may be disrupted." });
    } else if (s.has("delete")) {
      results.push({ risk: "dangerous", explanation: "Terraform will delete a subnet. Workloads and network interfaces in that subnet must move first." });
    } else if (s.has("update")) {
      results.push({ risk: "review", explanation: "Terraform will update subnet configuration. Review CIDR, availability zone, public IP, and routing assumptions." });
    }
    if (attributeChanged(change, "map_public_ip_on_launch")) {
      results.push({ risk: "dangerous", explanation: "Subnet map_public_ip_on_launch is changing. New instances may gain or lose public internet reachability." });
    }
  } else if (type === "aws_route_table" || type === "aws_route_table_association") {
    if (s.has("delete") && s.has("create")) {
      results.push({ risk: "dangerous", explanation: "Terraform will replace route table topology. Subnet egress, ingress, and private/public boundaries may shift." });
    } else if (s.has("delete")) {
      results.push({ risk: "dangerous", explanation: "Terraform will delete route table topology. Attached subnets may lose expected routing." });
    } else if (s.has("update")) {
      results.push({ risk: "review", explanation: "Terraform will update route table topology. Review subnet associations and default route behavior." });
    }
  } else if (type === "aws_route") {
    if (s.has("delete") && s.has("create")) {
      results.push({ risk: "dangerous", explanation: "Terraform will replace a route. Traffic may briefly blackhole or move to a different network boundary." });
    } else if (s.has("delete")) {
      results.push({ risk: "dangerous", explanation: "Terraform will delete a route. Dependent traffic may lose connectivity immediately." });
    } else if (s.has("update")) {
      results.push({ risk: "review", explanation: "Terraform will update a route. Review destination CIDRs and next-hop targets for reachability impact." });
    }
    if (routeOpensInternetPath(change)) {
      results.push({ risk: "dangerous", explanation: "This route appears to add a default route to an internet gateway. Confirm the attached subnet is intended to be public." });
    }
  } else if (type === "aws_nat_gateway") {
    if (s.has("delete") && s.has("create")) {
      results.push({ risk: "dangerous", explanation: "Terraform will replace a NAT gateway. Private subnet egress may be interrupted until routes point at the new gateway." });
    } else if (s.has("delete")) {
      results.push({ risk: "dangerous", explanation: "Terraform will delete a NAT gateway. Private subnet egress for patching, pulls, and outbound calls may stop." });
    } else if (s.has("create") || s.has("update")) {
      results.push({ risk: "review", explanation: "Terraform will change a NAT gateway. Review egress routing, AZ placement, and elastic IP dependencies." });
    }
  } else if (type === "aws_internet_gateway") {
    if (s.has("delete") && s.has("create")) {
      results.push({ risk: "dangerous", explanation: "Terraform will replace an internet gateway. Public subnet ingress and egress may be interrupted." });
    } else if (s.has("delete")) {
      results.push({ risk: "dangerous", explanation: "Terraform will delete an internet gateway. Public subnet connectivity through that VPC will stop." });
    } else if (s.has("create") || s.has("update")) {
      results.push({ risk: "review", explanation: "Terraform will change an internet gateway. Review which subnets and routes should become internet reachable." });
    }
  }

  return results;
}

// CloudWatch / Observability
function observabilityRules(type, actions, change) {
  const s = new Set(actions);
  const results = [];

  if (type === "aws_cloudwatch_metric_alarm") {
    if (s.has("delete")) {
      results.push({ risk: "dangerous", explanation: "Terraform will delete a CloudWatch alarm. Detection and incident response coverage may be reduced." });
    } else if (s.has("update")) {
      results.push({ risk: "review", explanation: "Terraform will update a CloudWatch alarm. Review threshold, period, evaluation, and action changes for detection impact." });
    }
    if (["alarm_actions", "ok_actions", "insufficient_data_actions", "threshold", "evaluation_periods", "datapoints_to_alarm"].some(k => attributeChanged(change, k))) {
      results.push({ risk: "review", explanation: "CloudWatch alarm sensitivity or notification actions are changing. Confirm alerts still reach the right responders." });
    }
  } else if (type === "aws_cloudwatch_event_rule" || type === "aws_cloudwatch_event_target") {
    const label = type === "aws_cloudwatch_event_rule" ? "EventBridge rule" : "EventBridge target";
    if (s.has("delete")) {
      results.push({ risk: "dangerous", explanation: `Terraform will delete an ${label}. Automated detection, routing, or remediation may stop.` });
    } else if (s.has("update")) {
      results.push({ risk: "review", explanation: `Terraform will update an ${label}. Review event pattern, schedule, target, and retry behavior.` });
    }
    if (["event_pattern", "schedule_expression", "arn", "role_arn"].some(k => attributeChanged(change, k))) {
      results.push({ risk: "review", explanation: `${label} routing criteria or destination is changing. Security events may stop reaching the expected workflow.` });
    }
  } else if (type === "aws_cloudwatch_log_group") {
    if (s.has("delete")) {
      results.push({ risk: "irreversible", explanation: "Terraform will delete a CloudWatch log group. Log history used for investigations and audit evidence may be removed." });
    } else if (s.has("update")) {
      results.push({ risk: "review", explanation: "Terraform will update a CloudWatch log group. Review retention, encryption, and subscription changes." });
    }
    if (retentionDecreased(change, "retention_in_days")) {
      results.push({ risk: "dangerous", explanation: "CloudWatch log retention is decreasing. Investigation and audit lookback windows may shrink." });
    }
  }

  return results;
}

// ── Main classifier ────────────────────────────────────────────────────

function classifyChange(resourceType, actions, change) {
  const baseline = {
    risk: baselineRisk(actions),
    explanation: baselineExplanation(actions),
  };

  const candidates = ruleCandidates(resourceType, actions, change);
  let result = baseline;
  for (const c of candidates) {
    result = maxRiskResult(result, c);
  }

  return result;
}

function ruleCandidates(resourceType, actions, change) {
  const s = new Set(actions);
  const rt = resourceType || "";

  if (["aws_db_instance", "aws_rds_cluster"].includes(rt)) {
    return rdsRules(rt, actions, change);
  }
  if (["aws_s3_bucket", "aws_s3_bucket_acl", "aws_s3_bucket_policy"].includes(rt)) {
    return s3Rules(rt, actions, change);
  }
  if (rt === "aws_kms_key") {
    return kmsRules(actions);
  }
  if (["aws_iam_role", "aws_iam_policy", "aws_iam_role_policy"].includes(rt)) {
    return iamRules(rt, actions, change);
  }
  if (rt === "aws_route53_zone") {
    return route53Rules(actions);
  }
  if (rt === "aws_eks_node_group") {
    return eksNodeGroupRules(actions);
  }
  if (rt === "aws_ecs_service") {
    return ecsServiceRules(actions, change);
  }
  if (["aws_lb", "aws_lb_listener", "aws_lb_listener_rule", "aws_lb_target_group", "aws_lb_target_group_attachment"].includes(rt)) {
    return lbRules(rt, actions, change);
  }
  if (["aws_lambda_function", "aws_lambda_alias", "aws_lambda_event_source_mapping"].includes(rt)) {
    return lambdaRules(rt, actions, change);
  }
  if (["aws_ecr_repository", "aws_ecr_repository_policy", "aws_ecr_lifecycle_policy", "aws_sqs_queue", "aws_sqs_queue_policy", "aws_glue_catalog_database", "aws_glue_catalog_table", "aws_glue_job"].includes(rt)) {
    return platformServiceRules(rt, actions, change);
  }
  if (["aws_security_group", "aws_security_group_rule", "aws_vpc_security_group_ingress_rule", "aws_vpc_security_group_egress_rule"].includes(rt)) {
    return securityGroupRules(rt, actions, change);
  }
  if (["aws_subnet", "aws_route_table", "aws_route", "aws_route_table_association", "aws_nat_gateway", "aws_internet_gateway"].includes(rt)) {
    return networkTopologyRules(rt, actions, change);
  }
  if (["aws_cloudwatch_metric_alarm", "aws_cloudwatch_event_rule", "aws_cloudwatch_event_target", "aws_cloudwatch_log_group"].includes(rt)) {
    return observabilityRules(rt, actions, change);
  }

  return [];
}

// ── Plan parsing ───────────────────────────────────────────────────────

function parsePlan(json) {
  const changes = [];
  const resourceChanges = json?.resource_changes || [];

  for (const rc of resourceChanges) {
    const actions = rc?.change?.actions || ["no-op"];
    const type = rc?.type || "unknown";
    const name = rc?.address || rc?.name || "unknown";
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
  module.exports = { parsePlan, matchCompliance, summarize, classifyChange, baselineRisk, baselineExplanation, ruleCandidates };
}
