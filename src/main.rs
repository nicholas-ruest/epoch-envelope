use std::{fs, path::PathBuf, process::ExitCode};

use clap::{Parser, ValueEnum};
use epoch_envelope::{AuditError, Plan, Policy, Verdict, audit};

#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    /// TOML reliability policy.
    #[arg(long)]
    policy: PathBuf,

    /// JSON execution plan to audit.
    #[arg(long)]
    plan: PathBuf,

    /// Report representation.
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

fn load(cli: &Cli) -> Result<(Policy, Plan), AuditError> {
    let policy_text = fs::read_to_string(&cli.policy).map_err(|source| AuditError::Read {
        path: cli.policy.clone(),
        source,
    })?;
    let plan_text = fs::read_to_string(&cli.plan).map_err(|source| AuditError::Read {
        path: cli.plan.clone(),
        source,
    })?;

    let policy = toml::from_str(&policy_text).map_err(AuditError::Policy)?;
    let plan = serde_json::from_str(&plan_text).map_err(AuditError::Plan)?;
    Ok((policy, plan))
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let (policy, plan) = match load(&cli) {
        Ok(inputs) => inputs,
        Err(error) => {
            eprintln!("epoch-envelope: {error}");
            return ExitCode::from(1);
        }
    };

    let report = match audit(&policy, &plan) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("epoch-envelope: {error}");
            return ExitCode::from(1);
        }
    };

    match cli.format {
        OutputFormat::Text => print!("{report}"),
        OutputFormat::Json => match serde_json::to_string_pretty(&report) {
            Ok(json) => println!("{json}"),
            Err(error) => {
                eprintln!("epoch-envelope: could not serialize report: {error}");
                return ExitCode::from(1);
            }
        },
    }

    match report.verdict {
        Verdict::Allow => ExitCode::SUCCESS,
        Verdict::Block => ExitCode::from(2),
    }
}
