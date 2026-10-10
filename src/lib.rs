use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    path::PathBuf,
};

use chrono::{DateTime, FixedOffset};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const PPM_SCALE: u64 = 1_000_000;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub schema_version: u32,
    pub limits: Limits,
    #[serde(default)]
    pub expected_epochs: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub max_failure_probability_ppm: u64,
    pub max_residual_bias_ppm: u64,
    pub max_cost_microunits: u64,
    pub max_shots: u64,
    pub max_critical_path_ms: u64,
    pub max_decoder_latency_ms: u64,
    pub max_calibration_age_seconds: i64,
    #[serde(default)]
    pub require_model_fit: bool,
    #[serde(default)]
    pub required_epoch_kinds: BTreeSet<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub schema_version: u32,
    pub plan_id: String,
    pub evaluated_at: String,
    pub model_fit_passed: bool,
    pub residual_bias_ppm: u64,
    pub decoder_latency_ms: u64,
    pub epochs: Vec<Epoch>,
    pub stages: Vec<Stage>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Epoch {
    pub kind: String,
    pub value: String,
    #[serde(default)]
    pub observed_at: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage {
    pub id: String,
    #[serde(default)]
    pub depends_on: Vec<String>,
    pub failure_probability_ppm: u64,
    pub cost_microunits: u64,
    pub shots: u64,
    pub duration_ms: u64,
    #[serde(default)]
    pub epoch_refs: BTreeMap<String, String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Verdict {
    Allow,
    Block,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub schema_version: u32,
    pub plan_id: String,
    pub verdict: Verdict,
    pub metrics: Metrics,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Serialize)]
pub struct Metrics {
    pub failure_probability_ppm: u64,
    pub max_failure_probability_ppm: u64,
    pub residual_bias_ppm: u64,
    pub max_residual_bias_ppm: u64,
    pub total_cost_microunits: u64,
    pub max_cost_microunits: u64,
    pub total_shots: u64,
    pub max_shots: u64,
    pub critical_path_ms: Option<u64>,
    pub max_critical_path_ms: u64,
    pub decoder_latency_ms: u64,
    pub max_decoder_latency_ms: u64,
    pub calibration_age_seconds: Option<i64>,
    pub max_calibration_age_seconds: i64,
}

#[derive(Debug, Serialize)]
pub struct Finding {
    pub rule_id: &'static str,
    pub subject: String,
    pub message: String,
}

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("cannot read {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid policy TOML: {0}")]
    Policy(#[source] toml::de::Error),
    #[error("invalid plan JSON: {0}")]
    Plan(#[source] serde_json::Error),
    #[error("invalid RFC 3339 timestamp '{value}' in {field}: {source}")]
    Time {
        field: String,
        value: String,
        #[source]
        source: chrono::ParseError,
    },
}

impl fmt::Display for Report {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(formatter, "{:?} {}", self.verdict, self.plan_id)?;
        writeln!(
            formatter,
            "failure_ppm: {}/{}",
            self.metrics.failure_probability_ppm, self.metrics.max_failure_probability_ppm
        )?;
        writeln!(
            formatter,
            "residual_bias_ppm: {}/{}",
            self.metrics.residual_bias_ppm, self.metrics.max_residual_bias_ppm
        )?;
        writeln!(
            formatter,
            "cost_microunits: {}/{}",
            self.metrics.total_cost_microunits, self.metrics.max_cost_microunits
        )?;
        writeln!(
            formatter,
            "shots: {}/{}",
            self.metrics.total_shots, self.metrics.max_shots
        )?;
        match self.metrics.critical_path_ms {
            Some(value) => writeln!(
                formatter,
                "critical_path_ms: {}/{}",
                value, self.metrics.max_critical_path_ms
            )?,
            None => writeln!(formatter, "critical_path_ms: unavailable")?,
        }
        writeln!(
            formatter,
            "decoder_latency_ms: {}/{}",
            self.metrics.decoder_latency_ms, self.metrics.max_decoder_latency_ms
        )?;
        match self.metrics.calibration_age_seconds {
            Some(value) => writeln!(
                formatter,
                "calibration_age_seconds: {}/{}",
                value, self.metrics.max_calibration_age_seconds
            )?,
            None => writeln!(formatter, "calibration_age_seconds: unavailable")?,
        }
        for finding in &self.findings {
            writeln!(
                formatter,
                "{} [{}] {}",
                finding.rule_id, finding.subject, finding.message
            )?;
        }
        Ok(())
    }
}

pub fn audit(policy: &Policy, plan: &Plan) -> Result<Report, AuditError> {
    let evaluated_at = parse_time("evaluated_at", &plan.evaluated_at)?;
    let mut findings = Vec::new();

    if policy.schema_version != 1 {
        push(
            &mut findings,
            "POLICY_SCHEMA_UNSUPPORTED",
            "policy",
            format!("schema version {} is unsupported", policy.schema_version),
        );
    }
    if plan.schema_version != 1 {
        push(
            &mut findings,
            "PLAN_SCHEMA_UNSUPPORTED",
            &plan.plan_id,
            format!("schema version {} is unsupported", plan.schema_version),
        );
    }
    if plan.plan_id.trim().is_empty() {
        push(
            &mut findings,
            "PLAN_ID_EMPTY",
            "plan",
            "plan_id must not be empty",
        );
    }

    let (epochs, calibration_age_seconds) =
        inspect_epochs(policy, plan, evaluated_at, &mut findings)?;
    inspect_model(policy, plan, &mut findings);
    inspect_stage_epochs(plan, &epochs, &mut findings);

    let mut failure_probability_ppm = 0_u64;
    let mut total_cost_microunits = 0_u64;
    let mut total_shots = 0_u64;
    for stage in &plan.stages {
        if stage.failure_probability_ppm > PPM_SCALE {
            push(
                &mut findings,
                "STAGE_FAILURE_RANGE",
                &stage.id,
                "failure_probability_ppm must not exceed 1,000,000",
            );
        }
        accumulate(
            &mut failure_probability_ppm,
            stage.failure_probability_ppm,
            "failure probability",
            &mut findings,
        );
        accumulate(
            &mut total_cost_microunits,
            stage.cost_microunits,
            "cost",
            &mut findings,
        );
        accumulate(&mut total_shots, stage.shots, "shots", &mut findings);
    }

    check_limit(
        failure_probability_ppm,
        policy.limits.max_failure_probability_ppm,
        "FAILURE_BUDGET_EXCEEDED",
        "plan",
        "failure_probability_ppm",
        &mut findings,
    );
    check_limit(
        total_cost_microunits,
        policy.limits.max_cost_microunits,
        "COST_BUDGET_EXCEEDED",
        "plan",
        "cost_microunits",
        &mut findings,
    );
    check_limit(
        total_shots,
        policy.limits.max_shots,
        "SHOT_BUDGET_EXCEEDED",
        "plan",
        "shots",
        &mut findings,
    );

    let critical_path_ms = inspect_graph(plan, &mut findings);
    if let Some(value) = critical_path_ms {
        check_limit(
            value,
            policy.limits.max_critical_path_ms,
            "CRITICAL_PATH_EXCEEDED",
            "plan",
            "critical_path_ms",
            &mut findings,
        );
    }

    let verdict = if findings.is_empty() {
        Verdict::Allow
    } else {
        Verdict::Block
    };
    Ok(Report {
        schema_version: 1,
        plan_id: plan.plan_id.clone(),
        verdict,
        metrics: Metrics {
            failure_probability_ppm,
            max_failure_probability_ppm: policy.limits.max_failure_probability_ppm,
            residual_bias_ppm: plan.residual_bias_ppm,
            max_residual_bias_ppm: policy.limits.max_residual_bias_ppm,
            total_cost_microunits,
            max_cost_microunits: policy.limits.max_cost_microunits,
            total_shots,
            max_shots: policy.limits.max_shots,
            critical_path_ms,
            max_critical_path_ms: policy.limits.max_critical_path_ms,
            decoder_latency_ms: plan.decoder_latency_ms,
            max_decoder_latency_ms: policy.limits.max_decoder_latency_ms,
            calibration_age_seconds,
            max_calibration_age_seconds: policy.limits.max_calibration_age_seconds,
        },
        findings,
    })
}

fn inspect_model(policy: &Policy, plan: &Plan, findings: &mut Vec<Finding>) {
    if policy.limits.require_model_fit && !plan.model_fit_passed {
        push(
            findings,
            "MODEL_FIT_FAILED",
            &plan.plan_id,
            "policy requires a passing model-fit check",
        );
    }
    check_limit(
        plan.residual_bias_ppm,
        policy.limits.max_residual_bias_ppm,
        "RESIDUAL_BIAS_EXCEEDED",
        &plan.plan_id,
        "residual_bias_ppm",
        findings,
    );
    check_limit(
        plan.decoder_latency_ms,
        policy.limits.max_decoder_latency_ms,
        "DECODER_LATENCY_EXCEEDED",
        &plan.plan_id,
        "decoder_latency_ms",
        findings,
    );
}

fn inspect_epochs(
    policy: &Policy,
    plan: &Plan,
    evaluated_at: DateTime<FixedOffset>,
    findings: &mut Vec<Finding>,
) -> Result<(BTreeMap<String, String>, Option<i64>), AuditError> {
    let mut epochs = BTreeMap::new();
    let mut calibration_age_seconds = None;
    for epoch in &plan.epochs {
        if epochs
            .insert(epoch.kind.clone(), epoch.value.clone())
            .is_some()
        {
            push(
                findings,
                "EPOCH_DUPLICATE",
                &epoch.kind,
                "epoch kind appears more than once",
            );
        }
        if epoch.kind == "calibration" {
            match &epoch.observed_at {
                Some(value) => {
                    let observed = parse_time("epochs.calibration.observed_at", value)?;
                    let age = evaluated_at.signed_duration_since(observed).num_seconds();
                    calibration_age_seconds = Some(age);
                    if age < 0 {
                        push(
                            findings,
                            "CALIBRATION_FROM_FUTURE",
                            "calibration",
                            format!("calibration is {} seconds ahead of evaluation", -age),
                        );
                    } else if age > policy.limits.max_calibration_age_seconds {
                        push(
                            findings,
                            "CALIBRATION_STALE",
                            "calibration",
                            format!(
                                "age {age} exceeds limit {} seconds",
                                policy.limits.max_calibration_age_seconds
                            ),
                        );
                    }
                }
                None => push(
                    findings,
                    "CALIBRATION_TIME_MISSING",
                    "calibration",
                    "calibration epoch requires observed_at",
                ),
            }
        }
    }

    for required in &policy.limits.required_epoch_kinds {
        if !epochs.contains_key(required) {
            push(
                findings,
                "EPOCH_REQUIRED",
                required,
                "required epoch is missing",
            );
        }
    }
    for (kind, expected) in &policy.expected_epochs {
        match epochs.get(kind) {
            Some(actual) if actual != expected => push(
                findings,
                "EPOCH_MISMATCH",
                kind,
                format!("expected '{expected}', found '{actual}'"),
            ),
            None => push(
                findings,
                "EPOCH_EXPECTED_MISSING",
                kind,
                format!("expected epoch '{expected}' is missing"),
            ),
            _ => {}
        }
    }
    Ok((epochs, calibration_age_seconds))
}

fn inspect_stage_epochs(
    plan: &Plan,
    epochs: &BTreeMap<String, String>,
    findings: &mut Vec<Finding>,
) {
    for stage in &plan.stages {
        if stage.epoch_refs.is_empty() {
            push(
                findings,
                "STAGE_LINEAGE_MISSING",
                &stage.id,
                "stage must bind at least one epoch",
            );
        }
        for (kind, referenced) in &stage.epoch_refs {
            match epochs.get(kind) {
                Some(actual) if actual != referenced => push(
                    findings,
                    "STAGE_EPOCH_DRIFT",
                    &stage.id,
                    format!("{kind} references '{referenced}' but plan binds '{actual}'"),
                ),
                None => push(
                    findings,
                    "STAGE_EPOCH_UNKNOWN",
                    &stage.id,
                    format!("references missing epoch kind '{kind}'"),
                ),
                _ => {}
            }
        }
    }
}

fn inspect_graph(plan: &Plan, findings: &mut Vec<Finding>) -> Option<u64> {
    let mut stages = BTreeMap::new();
    for stage in &plan.stages {
        if stages.insert(stage.id.clone(), stage).is_some() {
            push(
                findings,
                "STAGE_DUPLICATE",
                &stage.id,
                "stage id appears more than once",
            );
        }
    }
    if stages.len() != plan.stages.len() {
        return None;
    }
    if stages.is_empty() {
        push(
            findings,
            "PLAN_EMPTY",
            &plan.plan_id,
            "plan must contain at least one stage",
        );
        return None;
    }

    let mut indegree: BTreeMap<String, usize> = stages.keys().map(|id| (id.clone(), 0)).collect();
    let mut dependents: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut graph_valid = true;
    for stage in stages.values() {
        let unique_dependencies: BTreeSet<_> = stage.depends_on.iter().collect();
        if unique_dependencies.len() != stage.depends_on.len() {
            push(
                findings,
                "DEPENDENCY_DUPLICATE",
                &stage.id,
                "dependency list contains duplicates",
            );
            graph_valid = false;
        }
        for dependency in unique_dependencies {
            if dependency == &stage.id {
                push(
                    findings,
                    "DEPENDENCY_SELF",
                    &stage.id,
                    "stage depends on itself",
                );
                graph_valid = false;
            } else if !stages.contains_key(dependency) {
                push(
                    findings,
                    "DEPENDENCY_UNKNOWN",
                    &stage.id,
                    format!("dependency '{dependency}' does not exist"),
                );
                graph_valid = false;
            } else {
                *indegree.get_mut(&stage.id).expect("known stage") += 1;
                dependents
                    .entry(dependency.clone())
                    .or_default()
                    .insert(stage.id.clone());
            }
        }
    }
    if !graph_valid {
        return None;
    }

    let mut ready: BTreeSet<String> = indegree
        .iter()
        .filter(|(_, degree)| **degree == 0)
        .map(|(id, _)| id.clone())
        .collect();
    let mut order = Vec::new();
    while let Some(id) = ready.pop_first() {
        order.push(id.clone());
        if let Some(children) = dependents.get(&id) {
            for child in children {
                let degree = indegree.get_mut(child).expect("known dependent");
                *degree -= 1;
                if *degree == 0 {
                    ready.insert(child.clone());
                }
            }
        }
    }
    if order.len() != stages.len() {
        push(
            findings,
            "DEPENDENCY_CYCLE",
            &plan.plan_id,
            "stage graph contains a cycle",
        );
        return None;
    }

    let mut path_lengths = BTreeMap::new();
    for id in order {
        let stage = stages.get(&id).expect("topological stage exists");
        let parent_max = stage
            .depends_on
            .iter()
            .filter_map(|parent| path_lengths.get(parent))
            .copied()
            .max()
            .unwrap_or(0_u64);
        match parent_max.checked_add(stage.duration_ms) {
            Some(length) => {
                path_lengths.insert(id, length);
            }
            None => {
                push(
                    findings,
                    "RESOURCE_OVERFLOW",
                    &stage.id,
                    "critical path duration overflowed u64",
                );
                return None;
            }
        }
    }
    path_lengths.values().copied().max()
}

fn parse_time(field: &str, value: &str) -> Result<DateTime<FixedOffset>, AuditError> {
    DateTime::parse_from_rfc3339(value).map_err(|source| AuditError::Time {
        field: field.to_owned(),
        value: value.to_owned(),
        source,
    })
}

fn accumulate(total: &mut u64, value: u64, label: &str, findings: &mut Vec<Finding>) {
    match total.checked_add(value) {
        Some(sum) => *total = sum,
        None => {
            *total = u64::MAX;
            push(
                findings,
                "RESOURCE_OVERFLOW",
                "plan",
                format!("{label} sum overflowed u64"),
            );
        }
    }
}

fn check_limit(
    actual: u64,
    limit: u64,
    rule_id: &'static str,
    subject: &str,
    label: &str,
    findings: &mut Vec<Finding>,
) {
    if actual > limit {
        push(
            findings,
            rule_id,
            subject,
            format!("{label} {actual} exceeds limit {limit}"),
        );
    }
}

fn push(
    findings: &mut Vec<Finding>,
    rule_id: &'static str,
    subject: impl Into<String>,
    message: impl Into<String>,
) {
    findings.push(Finding {
        rule_id,
        subject: subject.into(),
        message: message.into(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> Policy {
        Policy {
            schema_version: 1,
            limits: Limits {
                max_failure_probability_ppm: 20_000,
                max_residual_bias_ppm: 5_000,
                max_cost_microunits: 10_000,
                max_shots: 2_000,
                max_critical_path_ms: 1_000,
                max_decoder_latency_ms: 20,
                max_calibration_age_seconds: 3_600,
                require_model_fit: true,
                required_epoch_kinds: ["calibration", "compiler", "decoder"]
                    .into_iter()
                    .map(str::to_owned)
                    .collect(),
            },
            expected_epochs: BTreeMap::from([("compiler".into(), "rust-1".into())]),
        }
    }

    fn plan() -> Plan {
        Plan {
            schema_version: 1,
            plan_id: "test-plan".into(),
            evaluated_at: "2026-10-09T21:30:00-04:00".into(),
            model_fit_passed: true,
            residual_bias_ppm: 1_000,
            decoder_latency_ms: 5,
            epochs: vec![
                Epoch {
                    kind: "calibration".into(),
                    value: "cal-7".into(),
                    observed_at: Some("2026-10-09T21:00:00-04:00".into()),
                },
                Epoch {
                    kind: "compiler".into(),
                    value: "rust-1".into(),
                    observed_at: None,
                },
                Epoch {
                    kind: "decoder".into(),
                    value: "decode-2".into(),
                    observed_at: None,
                },
            ],
            stages: vec![
                Stage {
                    id: "compile".into(),
                    depends_on: vec![],
                    failure_probability_ppm: 1_000,
                    cost_microunits: 100,
                    shots: 0,
                    duration_ms: 100,
                    epoch_refs: BTreeMap::from([("compiler".into(), "rust-1".into())]),
                },
                Stage {
                    id: "decode".into(),
                    depends_on: vec!["compile".into()],
                    failure_probability_ppm: 2_000,
                    cost_microunits: 200,
                    shots: 1_000,
                    duration_ms: 200,
                    epoch_refs: BTreeMap::from([("decoder".into(), "decode-2".into())]),
                },
            ],
        }
    }

    fn rules(report: &Report) -> BTreeSet<&str> {
        report.findings.iter().map(|item| item.rule_id).collect()
    }

    #[test]
    fn allows_plan_inside_envelope() {
        let report = audit(&policy(), &plan()).unwrap();
        assert_eq!(report.verdict, Verdict::Allow);
        assert_eq!(report.metrics.critical_path_ms, Some(300));
        assert_eq!(report.metrics.calibration_age_seconds, Some(1_800));
    }

    #[test]
    fn blocks_stale_calibration() {
        let mut input = plan();
        input.epochs[0].observed_at = Some("2026-10-09T19:00:00-04:00".into());
        let report = audit(&policy(), &input).unwrap();
        assert!(rules(&report).contains("CALIBRATION_STALE"));
    }

    #[test]
    fn blocks_epoch_drift() {
        let mut input = plan();
        input.stages[0]
            .epoch_refs
            .insert("compiler".into(), "old-compiler".into());
        let report = audit(&policy(), &input).unwrap();
        assert!(rules(&report).contains("STAGE_EPOCH_DRIFT"));
    }

    #[test]
    fn blocks_cycle() {
        let mut input = plan();
        input.stages[0].depends_on.push("decode".into());
        let report = audit(&policy(), &input).unwrap();
        assert!(rules(&report).contains("DEPENDENCY_CYCLE"));
        assert_eq!(report.metrics.critical_path_ms, None);
    }

    #[test]
    fn blocks_unknown_dependency() {
        let mut input = plan();
        input.stages[0].depends_on.push("missing".into());
        let report = audit(&policy(), &input).unwrap();
        assert!(rules(&report).contains("DEPENDENCY_UNKNOWN"));
    }

    #[test]
    fn blocks_failed_model_and_bias() {
        let mut input = plan();
        input.model_fit_passed = false;
        input.residual_bias_ppm = 5_001;
        let report = audit(&policy(), &input).unwrap();
        let found = rules(&report);
        assert!(found.contains("MODEL_FIT_FAILED"));
        assert!(found.contains("RESIDUAL_BIAS_EXCEEDED"));
    }

    #[test]
    fn blocks_resource_budgets() {
        let mut input = plan();
        input.stages[1].shots = 2_001;
        input.stages[1].cost_microunits = 10_001;
        input.stages[1].failure_probability_ppm = 20_001;
        input.stages[1].duration_ms = 1_001;
        let report = audit(&policy(), &input).unwrap();
        let found = rules(&report);
        assert!(found.contains("SHOT_BUDGET_EXCEEDED"));
        assert!(found.contains("COST_BUDGET_EXCEEDED"));
        assert!(found.contains("FAILURE_BUDGET_EXCEEDED"));
        assert!(found.contains("CRITICAL_PATH_EXCEEDED"));
    }

    #[test]
    fn blocks_missing_required_epoch() {
        let mut input = plan();
        input.epochs.retain(|epoch| epoch.kind != "decoder");
        let report = audit(&policy(), &input).unwrap();
        assert!(rules(&report).contains("EPOCH_REQUIRED"));
    }
}
