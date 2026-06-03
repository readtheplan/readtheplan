#!/usr/bin/env node
// classifier-parity.test.js — Parity test for classifier.js vs rules.py
// Run: node analysis/classifier-parity.test.js
// Requires Node >= 18

"use strict";

const fs = require("node:fs");
const path = require("node:path");

const {
  parsePlan,
  classifyChange,
  baselineRisk,
  baselineExplanation,
} = require("../site/playground/classifier.js");

// ── Helpers ─────────────────────────────────────────────────────────────

let passed = 0;
let failed = 0;
const failures = [];

function assert(name, fn) {
  try {
    fn();
    passed++;
  } catch (e) {
    failed++;
    failures.push({ name, error: e.message });
    console.error(`  FAIL ${name}: ${e.message}`);
  }
}

function eq(actual, expected, msg) {
  if (actual !== expected) {
    throw new Error(`${msg || "assertion failed"}: expected "${expected}", got "${actual}"`);
  }
}

function contains(haystack, needle, msg) {
  if (!haystack.includes(needle)) {
    throw new Error(`${msg || "assertion"}: "${haystack.substring(0, 120)}" does NOT contain "${needle}"`);
  }
}

function notContains(haystack, needle, msg) {
  if (haystack.includes(needle)) {
    throw new Error(`${msg || "assertion"}: should NOT contain "${needle}" but got "${haystack.substring(0, 120)}"`);
  }
}

function change(resourceType, actions, opts = {}) {
  const { before, after } = opts;
  const changeObj = { actions };
  if (before !== undefined) changeObj.before = before;
  if (after !== undefined) changeObj.after = after;
  return {
    type: resourceType,
    address: `${resourceType}.example`,
    name: "example",
    change: changeObj,
  };
}

function classify(rt, actions, opts = {}) {
  const { before, after } = opts;
  const changeObj = { actions };
  if (before !== undefined) changeObj.before = before;
  if (after !== undefined) changeObj.after = after;
  return classifyChange(rt, actions, changeObj);
}

function policy(statements) {
  return JSON.stringify({ Version: "2012-10-17", Statement: statements });
}

// ── Baseline Risk Tests ─────────────────────────────────────────────────

console.log("--- Baseline Risk Tests ---");

assert("empty actions → review", () => eq(baselineRisk([]), "review"));
assert("unknown action only → review", () => eq(baselineRisk(["bogus"]), "review"));
assert("create + unknown → review (ADR 0003)", () => eq(baselineRisk(["create", "bogus"]), "review"));
assert("create only → safe", () => eq(baselineRisk(["create"]), "safe"));
assert("create + no-op → safe", () => eq(baselineRisk(["create", "no-op"]), "safe"));
assert("delete → irreversible", () => eq(baselineRisk(["delete"]), "irreversible"));
assert("delete + create → dangerous", () => eq(baselineRisk(["delete", "create"]), "dangerous"));
assert("update → review", () => eq(baselineRisk(["update"]), "review"));
assert("no-op → safe", () => eq(baselineRisk(["no-op"]), "safe"));
assert("read → safe", () => eq(baselineRisk(["read"]), "safe"));
assert("create + update → review", () => eq(baselineRisk(["create", "update"]), "review"));

// ── Baseline Explanation Tests ─────────────────────────────────────────

console.log("--- Baseline Explanation Tests ---");

assert("create explanation", () => contains(baselineExplanation(["create"]), "create a new resource"));
assert("delete explanation", () => contains(baselineExplanation(["delete"]), "delete this resource"));
assert("update explanation", () => contains(baselineExplanation(["update"]), "update this resource in place"));
assert("replace explanation", () => contains(baselineExplanation(["create", "delete"]), "replace"));
assert("unknown explanation", () => contains(baselineExplanation(["bogus"]), "missing or unknown"));

// ── RDS Rules ───────────────────────────────────────────────────────────

console.log("--- RDS Tests ---");

assert("RDS instance delete+create → dangerous with RDS details", () => {
  const r = classify("aws_db_instance", ["delete", "create"]);
  eq(r.risk, "dangerous");
  contains(r.explanation, "RDS instance");
  contains(r.explanation, "replace");
  contains(r.explanation, "snapshots");
});
assert("RDS cluster delete-only → irreversible (RDS rule wins when risks equal)", () => {
  const r = classify("aws_rds_cluster", ["delete"]);
  eq(r.risk, "irreversible");
  contains(r.explanation, "RDS cluster");
  contains(r.explanation, "snapshot");
});
assert("RDS update → review with RDS details", () => {
  const r = classify("aws_db_instance", ["update"]);
  eq(r.risk, "review");
  contains(r.explanation, "RDS instance");
  contains(r.explanation, "backup");
});
assert("RDS major version bump → dangerous", () => {
  const r = classify("aws_rds_cluster", ["update"], {
    before: { engine_version: "13.8" },
    after: { engine_version: "14.1" },
  });
  eq(r.risk, "dangerous");
  contains(r.explanation, "major version");
});
assert("RDS same major version → review only (no major flag)", () => {
  const r = classify("aws_db_instance", ["update"], {
    before: { engine_version: "14.1" },
    after: { engine_version: "14.5" },
  });
  eq(r.risk, "review");
  notContains(r.explanation, "major version");
});

// ── S3 Rules ───────────────────────────────────────────────────────────

console.log("--- S3 Tests ---");

assert("S3 delete with force_destroy → irreversible with force_destroy details", () => {
  const r = classify("aws_s3_bucket", ["delete"], {
    before: { force_destroy: true },
  });
  eq(r.risk, "irreversible");
  contains(r.explanation, "force_destroy");
});
assert("S3 delete without force_destroy → irreversible with S3 details", () => {
  const r = classify("aws_s3_bucket", ["delete"]);
  eq(r.risk, "irreversible");
  contains(r.explanation, "S3 bucket");
  contains(r.explanation, "recovery");
});
assert("S3 update → review with S3 details", () => {
  const r = classify("aws_s3_bucket", ["update"]);
  eq(r.risk, "review");
  contains(r.explanation, "S3 bucket controls");
});
assert("S3 create → safe with S3 details", () => {
  const r = classify("aws_s3_bucket", ["create"]);
  eq(r.risk, "safe");
  contains(r.explanation, "S3 bucket");
  contains(r.explanation, "public access blocks");
});
assert("S3 policy public exposure → dangerous", () => {
  const r = classify("aws_s3_bucket_policy", ["update"], {
    before: { policy: policy([]) },
    after: {
      policy: policy([
        { Effect: "Allow", Principal: "*", Action: "s3:GetObject" },
      ]),
    },
  });
  eq(r.risk, "dangerous");
  contains(r.explanation, "public access");
});

// ── KMS Rules ──────────────────────────────────────────────────────────

console.log("--- KMS Tests ---");

assert("KMS delete → irreversible with KMS details", () => {
  const r = classify("aws_kms_key", ["delete"]);
  eq(r.risk, "irreversible");
  contains(r.explanation, "KMS key");
  contains(r.explanation, "deletion");
});
assert("KMS replace → dangerous with replace details", () => {
  const r = classify("aws_kms_key", ["delete", "create"]);
  eq(r.risk, "dangerous");
  contains(r.explanation, "replace");
  contains(r.explanation, "KMS key");
});
assert("KMS update → review with KMS details", () => {
  const r = classify("aws_kms_key", ["update"]);
  eq(r.risk, "review");
  contains(r.explanation, "KMS key");
});
assert("KMS create only → safe (baseline, no KMS-specific rule)", () => {
  const r = classify("aws_kms_key", ["create"]);
  eq(r.risk, "safe");
  contains(r.explanation, "create a new resource");
});

// ── IAM Rules ──────────────────────────────────────────────────────────

console.log("--- IAM Tests ---");

assert("IAM role delete → irreversible with IAM details", () => {
  const r = classify("aws_iam_role", ["delete"]);
  eq(r.risk, "irreversible");
  contains(r.explanation, "delete IAM");
  contains(r.explanation, "workloads");
});
assert("IAM policy delete → irreversible (BUG FIX: was dangerous in old JS)", () => {
  const r = classify("aws_iam_policy", ["delete"]);
  eq(r.risk, "irreversible");
  contains(r.explanation, "delete IAM");
});
assert("IAM update → review with IAM details", () => {
  const r = classify("aws_iam_policy", ["update"]);
  eq(r.risk, "review");
  contains(r.explanation, "IAM authorization");
});
assert("IAM role trust policy change → dangerous", () => {
  const r = classify("aws_iam_role", ["update"], {
    before: { assume_role_policy: policy([]) },
    after: {
      assume_role_policy: policy([
        { Effect: "Allow", Principal: { AWS: "*" }, Action: "sts:AssumeRole" },
      ]),
    },
  });
  eq(r.risk, "dangerous");
  contains(r.explanation, "trust policy");
});
assert("IAM deny statement removal → dangerous", () => {
  const r = classify("aws_iam_policy", ["update"], {
    before: { policy: policy([{ Effect: "Deny", Action: "iam:*" }]) },
    after: { policy: policy([{ Effect: "Allow", Action: "s3:GetObject" }]) },
  });
  eq(r.risk, "dangerous");
  contains(r.explanation, "remove deny statements");
});
assert("IAM create with no deny removal → review (not dangerous)", () => {
  const r = classify("aws_iam_policy", ["create"]);
  eq(r.risk, "safe"); // baseline safe for create
  notContains(r.explanation, "deny");
});

// ── Route53 Rules ──────────────────────────────────────────────────────

console.log("--- Route53 Tests ---");

assert("Route53 delete → irreversible with zone details", () => {
  const r = classify("aws_route53_zone", ["delete"]);
  eq(r.risk, "irreversible");
  contains(r.explanation, "hosted zone");
  contains(r.explanation, "DNS");
});
assert("Route53 replace → dangerous", () => {
  const r = classify("aws_route53_zone", ["delete", "create"]);
  eq(r.risk, "dangerous");
  contains(r.explanation, "replace");
  contains(r.explanation, "Route53");
});
assert("Route53 update → review", () => {
  const r = classify("aws_route53_zone", ["update"]);
  eq(r.risk, "review");
  contains(r.explanation, "hosted zone");
  contains(r.explanation, "delegation");
});

// ── EKS Rules ──────────────────────────────────────────────────────────

console.log("--- EKS Tests ---");

assert("EKS node group replace → dangerous", () => {
  const r = classify("aws_eks_node_group", ["delete", "create"]);
  eq(r.risk, "dangerous");
  contains(r.explanation, "EKS node group");
  contains(r.explanation, "pod evictions");
});
assert("EKS node group delete → irreversible (EKS rule wins when risks equal)", () => {
  const r = classify("aws_eks_node_group", ["delete"]);
  eq(r.risk, "irreversible");
  contains(r.explanation, "EKS node group");
  contains(r.explanation, "replacement");
});
assert("EKS node group update → review with EKS details", () => {
  const r = classify("aws_eks_node_group", ["update"]);
  eq(r.risk, "review");
  contains(r.explanation, "EKS node group");
  contains(r.explanation, "rollout");
});

// ── ECS Rules ──────────────────────────────────────────────────────────

console.log("--- ECS Tests ---");

assert("ECS service delete → irreversible (ECS rule wins when risks equal)", () => {
  const r = classify("aws_ecs_service", ["delete"]);
  eq(r.risk, "irreversible");
  contains(r.explanation, "ECS service");
  contains(r.explanation, "tasks");
});
assert("ECS service replace → dangerous with ECS details", () => {
  const r = classify("aws_ecs_service", ["delete", "create"]);
  eq(r.risk, "dangerous");
  contains(r.explanation, "ECS service");
  contains(r.explanation, "drained");
});
assert("ECS update → review with ECS details", () => {
  const r = classify("aws_ecs_service", ["update"]);
  eq(r.risk, "review");
  contains(r.explanation, "ECS service");
  contains(r.explanation, "deployment");
});
assert("ECS force_new_deployment → dangerous", () => {
  const r = classify("aws_ecs_service", ["update"], {
    before: { force_new_deployment: false },
    after: { force_new_deployment: true },
  });
  eq(r.risk, "dangerous");
  contains(r.explanation, "force_new_deployment");
  contains(r.explanation, "rolling restart");
});
assert("ECS launch_type change → review", () => {
  const r = classify("aws_ecs_service", ["update"], {
    before: { launch_type: "EC2" },
    after: { launch_type: "FARGATE" },
  });
  eq(r.risk, "review");
  contains(r.explanation, "launch_type");
});

// ── Load Balancer Tests ────────────────────────────────────────────────

console.log("--- LB Tests ---");

assert("LB delete → irreversible with LB details", () => {
  const r = classify("aws_lb", ["delete"]);
  eq(r.risk, "irreversible");
  contains(r.explanation, "load balancer");
  contains(r.explanation, "listeners");
});
assert("LB replace → dangerous", () => {
  const r = classify("aws_lb", ["delete", "create"]);
  eq(r.risk, "dangerous");
  contains(r.explanation, "replace");
  contains(r.explanation, "DNS rebinding");
});
assert("LB scheme change → irreversible", () => {
  const r = classify("aws_lb", ["update"], {
    before: { internal: true },
    after: { internal: false },
  });
  eq(r.risk, "irreversible");
  contains(r.explanation, "scheme");
});
assert("LB listener delete → irreversible (baseline wins over dangerous)", () => {
  // Python: baseline irreversible(3) > rule dangerous(2). baseline wins.
  const r = classify("aws_lb_listener", ["delete"]);
  eq(r.risk, "irreversible");
  contains(r.explanation, "delete this resource");
});
assert("LB listener update → review (no attr change triggers generic)", () => {
  const r = classify("aws_lb_listener", ["update"]);
  eq(r.risk, "review");
  contains(r.explanation, "update this resource");
});
assert("LB listener default_action change → dangerous", () => {
  const r = classify("aws_lb_listener", ["update"], {
    before: { default_action: [{ type: "forward", target_group_arn: "old" }] },
    after: { default_action: [{ type: "forward", target_group_arn: "new" }] },
  });
  eq(r.risk, "dangerous");
  contains(r.explanation, "default_action");
});
assert("LB listener port change → dangerous", () => {
  const r = classify("aws_lb_listener", ["update"], {
    before: { port: 80, protocol: "HTTP" },
    after: { port: 443, protocol: "HTTPS" },
  });
  eq(r.risk, "dangerous");
  contains(r.explanation, "port or protocol");
});
assert("LB listener rule priority change → review", () => {
  const r = classify("aws_lb_listener_rule", ["update"], {
    before: { priority: 100 },
    after: { priority: 50 },
  });
  eq(r.risk, "review");
  contains(r.explanation, "priority");
});
assert("LB target group replace → dangerous", () => {
  const r = classify("aws_lb_target_group", ["delete", "create"]);
  eq(r.risk, "dangerous");
  contains(r.explanation, "target group");
  contains(r.explanation, "registrations");
});
assert("LB target group delete → irreversible", () => {
  const r = classify("aws_lb_target_group", ["delete"]);
  eq(r.risk, "irreversible");
  contains(r.explanation, "target group");
});
assert("LB target group target_type change → dangerous", () => {
  const r = classify("aws_lb_target_group", ["delete", "create"], {
    before: { target_type: "instance" },
    after: { target_type: "ip" },
  });
  eq(r.risk, "dangerous");
  contains(r.explanation, "target_type");
});
assert("LB target group health check change → review", () => {
  const r = classify("aws_lb_target_group", ["update"], {
    before: { health_check: { interval: 30, threshold: 3 } },
    after: { health_check: { interval: 5, threshold: 2 } },
  });
  eq(r.risk, "review");
  contains(r.explanation, "health check");
});
assert("LB target group attachment detach → irreversible (baseline wins over review)", () => {
  // Python: baseline irreversible(3) > rule review(1). baseline wins.
  const r = classify("aws_lb_target_group_attachment", ["delete"]);
  eq(r.risk, "irreversible");
  contains(r.explanation, "delete this resource");
});

// ── Lambda Tests ───────────────────────────────────────────────────────

console.log("--- Lambda Tests ---");

assert("Lambda function delete → irreversible (baseline only, no lambda rule)", () => {
  // Python: lambdaRules returns [] for delete because "update" not in action_set
  const r = classify("aws_lambda_function", ["delete"]);
  eq(r.risk, "irreversible");
  contains(r.explanation, "delete this resource");
});
assert("Lambda package_type change → dangerous", () => {
  const r = classify("aws_lambda_function", ["update"], {
    before: { package_type: "Zip" },
    after: { package_type: "Image" },
  });
  eq(r.risk, "dangerous");
  contains(r.explanation, "package_type");
});
assert("Lambda code_signing change → review", () => {
  const r = classify("aws_lambda_function", ["update"], {
    before: { code_signing_config_arn: "arn:aws:lambda:us-east-1:123:csc/old" },
    after: { code_signing_config_arn: "arn:aws:lambda:us-east-1:123:csc/new" },
  });
  eq(r.risk, "review");
  contains(r.explanation, "code_signing_config_arn");
});
assert("Lambda vpc_config change → review", () => {
  const r = classify("aws_lambda_function", ["update"], {
    before: { vpc_config: null },
    after: { vpc_config: { subnet_ids: ["subnet-123"], security_group_ids: ["sg-123"] } },
  });
  eq(r.risk, "review");
  contains(r.explanation, "vpc_config");
});
assert("Lambda runtime major change → review", () => {
  const r = classify("aws_lambda_function", ["update"], {
    before: { runtime: "nodejs18.x" },
    after: { runtime: "nodejs20.x" },
  });
  eq(r.risk, "review");
  contains(r.explanation, "runtime");
});
assert("Lambda role change → review", () => {
  const r = classify("aws_lambda_function", ["update"], {
    before: { role: "arn:aws:iam::123:role/old" },
    after: { role: "arn:aws:iam::123:role/new" },
  });
  eq(r.risk, "review");
  contains(r.explanation, "execution role");
});
assert("Lambda runtime minor change → no runtime flag", () => {
  const r = classify("aws_lambda_function", ["update"], {
    before: { runtime: "python3.11" },
    after: { runtime: "python3.12" },
  });
  // Same major (python3), should NOT reference runtime change
  notContains(r.explanation, "runtime major version");
  notContains(r.explanation, "deprecated");
});
assert("Lambda runtime deprecated → dangerous", () => {
  const r = classify("aws_lambda_function", ["update"], {
    before: { runtime: "python3.8" },
    after: { runtime: "python3.9" },
  });
  eq(r.risk, "dangerous");
  contains(r.explanation, "deprecated");
});
assert("Lambda alias/event_source_mapping → baseline only", () => {
  // Python returns [] for non-function Lambda types
  const r1 = classify("aws_lambda_alias", ["update"]);
  eq(r1.risk, "review");
  notContains(r1.explanation, "package_type");
  const r2 = classify("aws_lambda_event_source_mapping", ["delete"]);
  eq(r2.risk, "irreversible");
  notContains(r2.explanation, "Lambda");
});

// ── Platform Service Tests (ECR, SQS, Glue) ───────────────────────────

console.log("--- Platform Service Tests ---");

assert("ECR repository delete → irreversible with ECR details", () => {
  const r = classify("aws_ecr_repository", ["delete"]);
  eq(r.risk, "irreversible");
  contains(r.explanation, "ECR repository");
  contains(r.explanation, "Container images");
});
assert("ECR repository replace → dangerous", () => {
  const r = classify("aws_ecr_repository", ["delete", "create"]);
  eq(r.risk, "dangerous");
  contains(r.explanation, "ECR repository");
  contains(r.explanation, "Image URLs");
});
assert("ECR repository update → review", () => {
  const r = classify("aws_ecr_repository", ["update"]);
  eq(r.risk, "review");
  contains(r.explanation, "ECR repository");
});
assert("ECR lifecycle policy delete → irreversible (baseline wins over review)", () => {
  const r = classify("aws_ecr_lifecycle_policy", ["delete"]);
  eq(r.risk, "irreversible");
  contains(r.explanation, "delete this resource");
});
assert("ECR lifecycle policy update → review", () => {
  const r = classify("aws_ecr_lifecycle_policy", ["update"]);
  eq(r.risk, "review");
  contains(r.explanation, "ECR lifecycle");
});
assert("ECR repository policy delete → irreversible (baseline over dangerous)", () => {
  const r = classify("aws_ecr_repository_policy", ["delete"]);
  eq(r.risk, "irreversible");
  contains(r.explanation, "delete this resource");
});
assert("SQS queue delete → irreversible with SQS details", () => {
  const r = classify("aws_sqs_queue", ["delete"]);
  eq(r.risk, "irreversible");
  contains(r.explanation, "SQS queue");
});
assert("SQS queue policy public access → dangerous", () => {
  const r = classify("aws_sqs_queue_policy", ["update"], {
    before: { policy: policy([]) },
    after: {
      policy: policy([
        { Effect: "Allow", Principal: "*", Action: "sqs:SendMessage" },
      ]),
    },
  });
  eq(r.risk, "dangerous");
  contains(r.explanation, "public access");
});
assert("Glue catalog database delete → irreversible (baseline wins over dangerous)", () => {
  const r = classify("aws_glue_catalog_database", ["delete"]);
  eq(r.risk, "irreversible");
  contains(r.explanation, "delete this resource");
});
assert("Glue catalog table delete → irreversible (baseline wins over dangerous)", () => {
  const r = classify("aws_glue_catalog_table", ["delete"]);
  eq(r.risk, "irreversible");
  contains(r.explanation, "delete this resource");
});
assert("Glue job delete → irreversible with Glue details", () => {
  const r = classify("aws_glue_job", ["delete"]);
  eq(r.risk, "irreversible");
  contains(r.explanation, "Glue job");
});
assert("Glue job role_arn change → review", () => {
  const r = classify("aws_glue_job", ["update"], {
    before: { role_arn: "arn:aws:iam::123:role/old" },
    after: { role_arn: "arn:aws:iam::123:role/new" },
  });
  eq(r.risk, "review");
  contains(r.explanation, "role_arn");
});

// ── Security Group Tests ───────────────────────────────────────────────

console.log("--- Security Group Tests ---");

assert("Security group delete → irreversible (baseline wins over dangerous)", () => {
  const r = classify("aws_security_group", ["delete"]);
  eq(r.risk, "irreversible");
  contains(r.explanation, "delete this resource");
});
assert("Security group replace → dangerous", () => {
  const r = classify("aws_security_group", ["delete", "create"]);
  eq(r.risk, "dangerous");
  contains(r.explanation, "security group");
});
assert("Security group update → review with SG details", () => {
  const r = classify("aws_security_group", ["update"]);
  eq(r.risk, "review");
  contains(r.explanation, "security group rules");
});
assert("Security group open ingress → dangerous", () => {
  const r = classify("aws_security_group", ["update"], {
    before: {
      ingress: [
        { from_port: 443, to_port: 443, protocol: "tcp", cidr_blocks: ["10.0.0.0/16"] },
      ],
    },
    after: {
      ingress: [
        { from_port: 443, to_port: 443, protocol: "tcp", cidr_blocks: ["0.0.0.0/0"] },
      ],
    },
  });
  eq(r.risk, "dangerous");
  contains(r.explanation, "internet-wide access");
});
assert("VPC SG ingress rule open IPv4 → dangerous", () => {
  const r = classify("aws_vpc_security_group_ingress_rule", ["create"], {
    after: {
      from_port: 22,
      to_port: 22,
      ip_protocol: "tcp",
      cidr_ipv4: "0.0.0.0/0",
    },
  });
  eq(r.risk, "dangerous");
  contains(r.explanation, "internet-wide access");
});
assert("VPC SG egress rule non-public → review with SG details", () => {
  const r = classify("aws_vpc_security_group_egress_rule", ["update"], {
    before: { cidr_ipv4: "10.0.0.0/16" },
    after: { cidr_ipv4: "172.16.0.0/12" },
  });
  eq(r.risk, "review");
  contains(r.explanation, "security group rules");
});

// ── Network Topology Tests ─────────────────────────────────────────────

console.log("--- Network Topology Tests ---");

assert("Route to internet gateway → dangerous", () => {
  const r = classify("aws_route", ["create"], {
    after: {
      destination_cidr_block: "0.0.0.0/0",
      gateway_id: "igw-example",
    },
  });
  eq(r.risk, "dangerous");
  contains(r.explanation, "internet gateway");
});
assert("NAT gateway delete → irreversible (baseline wins over dangerous)", () => {
  const r = classify("aws_nat_gateway", ["delete"]);
  eq(r.risk, "irreversible");
  contains(r.explanation, "delete this resource");
});
assert("Internet gateway delete → irreversible (baseline wins over dangerous)", () => {
  const r = classify("aws_internet_gateway", ["delete"]);
  eq(r.risk, "irreversible");
  contains(r.explanation, "delete this resource");
});
assert("Subnet map_public_ip change → dangerous", () => {
  const r = classify("aws_subnet", ["update"], {
    before: { map_public_ip_on_launch: false },
    after: { map_public_ip_on_launch: true },
  });
  eq(r.risk, "dangerous");
  contains(r.explanation, "map_public_ip");
});
assert("Subnet delete → irreversible (baseline wins over dangerous)", () => {
  const r = classify("aws_subnet", ["delete"]);
  eq(r.risk, "irreversible");
  contains(r.explanation, "delete this resource");
});
assert("Route table replace → dangerous", () => {
  const r = classify("aws_route_table", ["delete", "create"]);
  eq(r.risk, "dangerous");
  contains(r.explanation, "route table");
});
assert("Route delete → irreversible (baseline wins over dangerous)", () => {
  const r = classify("aws_route", ["delete"]);
  eq(r.risk, "irreversible");
  contains(r.explanation, "delete this resource");
});
assert("NAT gateway replace → dangerous", () => {
  const r = classify("aws_nat_gateway", ["delete", "create"]);
  eq(r.risk, "dangerous");
  contains(r.explanation, "NAT gateway");
});

// ── CloudWatch / Observability Tests ───────────────────────────────────

console.log("--- CloudWatch Tests ---");

assert("CloudWatch alarm delete → irreversible (baseline wins over dangerous)", () => {
  const r = classify("aws_cloudwatch_metric_alarm", ["delete"]);
  eq(r.risk, "irreversible");
  contains(r.explanation, "delete this resource");
});
assert("EventBridge rule delete → irreversible (baseline wins over dangerous)", () => {
  const r = classify("aws_cloudwatch_event_rule", ["delete"]);
  eq(r.risk, "irreversible");
  contains(r.explanation, "delete this resource");
});
assert("CloudWatch log group delete → irreversible with log details", () => {
  const r = classify("aws_cloudwatch_log_group", ["delete"]);
  eq(r.risk, "irreversible");
  contains(r.explanation, "log group");
});
assert("CloudWatch log retention decrease → dangerous", () => {
  const r = classify("aws_cloudwatch_log_group", ["update"], {
    before: { retention_in_days: 365 },
    after: { retention_in_days: 30 },
  });
  eq(r.risk, "dangerous");
  contains(r.explanation, "retention is decreasing");
});
assert("CloudWatch alarm sensitivity change → review", () => {
  const r = classify("aws_cloudwatch_metric_alarm", ["update"], {
    before: { threshold: 90, evaluation_periods: 5 },
    after: { threshold: 50, evaluation_periods: 3 },
  });
  eq(r.risk, "review");
  contains(r.explanation, "sensitivity");
});
assert("EventBridge rule pattern change → review", () => {
  const r = classify("aws_cloudwatch_event_rule", ["update"], {
    before: { event_pattern: JSON.stringify({ source: ["aws.ec2"] }) },
    after: { event_pattern: JSON.stringify({ source: ["aws.s3"] }) },
  });
  eq(r.risk, "review");
  contains(r.explanation, "routing criteria");
});

// ── Fixture Plan Tests ─────────────────────────────────────────────────

console.log("--- Fixture Plan Tests ---");

function loadPlan(filename) {
  const raw = fs.readFileSync(
    path.join(__dirname, "..", "site", "playground", filename),
    "utf8"
  );
  return JSON.parse(raw);
}

assert("fixture: floci-spike-create-plan matches Python", () => {
  const plan = loadPlan("floci-spike-create-plan.json");
  const changes = parsePlan(plan);
  const byAddr = {};
  for (const c of changes) byAddr[c.address] = c;

  eq(changes.length, 7, "7 resources");
  // All creates → safe
  eq(byAddr["aws_s3_bucket.static-assets"].risk, "safe");
  eq(byAddr["aws_dynamodb_table.sessions"].risk, "safe");
  eq(byAddr["aws_iam_role.lambda-exec"].risk, "safe");
});

assert("fixture: floci-spike-destroy-plan matches Python", () => {
  const plan = loadPlan("floci-spike-destroy-plan.json");
  const changes = parsePlan(plan);
  const byAddr = {};
  for (const c of changes) byAddr[c.address] = c;

  eq(changes.length, 7, "7 resources");
  // All deletes → irreversible
  eq(byAddr["aws_s3_bucket.static-assets"].risk, "irreversible");
  eq(byAddr["aws_dynamodb_table.sessions"].risk, "irreversible");
  eq(byAddr["aws_iam_role.lambda-exec"].risk, "irreversible");
});

assert("fixture: floci-spike-create-plan matches Python", () => {
  const plan = loadPlan("floci-spike-create-plan.json");
  const changes = parsePlan(plan);

  eq(changes.length, 7, "7 resources");
  for (const c of changes) {
    eq(c.risk, "safe", `${c.address} should be safe`);
  }
});

assert("fixture: floci-spike-destroy-plan matches Python", () => {
  const plan = loadPlan("floci-spike-destroy-plan.json");
  const changes = parsePlan(plan);
  const byAddr = {};
  for (const c of changes) byAddr[c.address] = c;

  eq(changes.length, 7, "7 resources");
  // S3 deletes: irreversible
  eq(byAddr["aws_s3_bucket.static-assets"].risk, "irreversible");
  eq(byAddr["aws_s3_bucket.cdn-logs"].risk, "irreversible");
  eq(byAddr["aws_s3_bucket.data-lake"].risk, "irreversible");
  // DynamoDB deletes: irreversible (baseline)
  eq(byAddr["aws_dynamodb_table.sessions"].risk, "irreversible");
  eq(byAddr["aws_dynamodb_table.users"].risk, "irreversible");
  // IAM role deletes: irreversible
  eq(byAddr["aws_iam_role.lambda-exec"].risk, "irreversible");
  eq(byAddr["aws_iam_role.ecs-task-role"].risk, "irreversible");
});

// ── Edge Cases ─────────────────────────────────────────────────────────

console.log("--- Edge Cases ---");

assert("unknown resource type falls back to baseline", () => {
  const r = classify("aws_unknown_type", ["update"]);
  eq(r.risk, "review");
  contains(r.explanation, "update this resource");
});
assert("no crash on empty change object", () => {
  const r = classify("aws_db_instance", ["update"], {});
  eq(r.risk, "review");
});
assert("deepEqual handles null vs object", () => {
  const r = classify("aws_lambda_function", ["update"], {
    before: { vpc_config: null },
    after: { vpc_config: { subnet_ids: ["sub-123"] } },
  });
  eq(r.risk, "review");
  contains(r.explanation, "vpc_config");
});
assert("no crash on missing before in change (force_destroy check)", () => {
  const r = classify("aws_s3_bucket", ["delete"], { after: { force_destroy: false } });
  eq(r.risk, "irreversible");
  contains(r.explanation, "S3 bucket");
});
assert("policy document JSON string parsing", () => {
  const r = classify("aws_iam_policy", ["update"], {
    before: { policy: JSON.stringify({ Version: "2012-10-17", Statement: [{ Effect: "Deny", Action: "*" }] }) },
    after: { policy: JSON.stringify({ Version: "2012-10-17", Statement: [{ Effect: "Allow", Action: "*" }] }) },
  });
  eq(r.risk, "dangerous");
  contains(r.explanation, "remove deny statements");
});
assert("S3 ACL public-read → dangerous", () => {
  const r = classify("aws_s3_bucket", ["update"], {
    before: { acl: "private" },
    after: { acl: "public-read" },
  });
  eq(r.risk, "dangerous");
  contains(r.explanation, "public access");
});
assert("SG ::/0 IPv6 detection → dangerous", () => {
  const r = classify("aws_vpc_security_group_ingress_rule", ["create"], {
    after: {
      from_port: 443,
      to_port: 443,
      ip_protocol: "tcp",
      cidr_ipv6: "::/0",
    },
  });
  eq(r.risk, "dangerous");
  contains(r.explanation, "internet-wide access");
});
assert("maxRiskResult returns candidate when risks equal", () => {
  // RDS delete (irreversible) + something else that also returns irreversible should show RDS explanation
  const r = classify("aws_rds_cluster", ["delete"]);
  eq(r.risk, "irreversible");
  contains(r.explanation, "RDS cluster");
  contains(r.explanation, "snapshot");
});

// ── Results ────────────────────────────────────────────────────────────

console.log(`\n${"=".repeat(50)}`);
console.log(`Results: ${passed} passed, ${failed} failed`);
if (failed > 0) {
  console.log(`\nFailures:`);
  for (const f of failures) {
    console.log(`  - ${f.name}: ${f.error}`);
  }
  process.exit(1);
} else {
  console.log(`All parity tests passed!`);
}
