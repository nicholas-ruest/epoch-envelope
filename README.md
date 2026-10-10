# epoch-envelope

`epoch-envelope` is a deterministic, fail-closed Rust CLI for auditing a directed execution plan against a frozen reliability and resource policy. It is useful when a hybrid scientific or data-processing job must prove that its calibration, compiler, decoder, model, cost, latency, and sampling assumptions still belong to the same execution epoch.

The first release is motivated by hybrid quantum/classical reliability planning, but the file formats are provider-neutral and the auditor never submits work to hardware.

## What it checks

- stage dependencies form a directed acyclic graph;
- required hardware, calibration, compiler, decoder, and noise-model epochs exist;
- the plan and every declared stage reference agree on epoch values;
- calibration evidence is present, not future-dated, and fresh enough;
- model fit, residual bias, and decoder latency satisfy policy;
- the conservative sum of stage failure upper bounds stays inside the envelope;
- total shots and cost stay inside their budgets;
- the DAG's critical path stays inside its wall-time budget.

An accepted plan exits `0`. A well-formed but rejected plan exits `2` and includes stable rule IDs. Input or I/O errors exit `1`.

## Install

Stable Rust is sufficient:

```console
cargo install --git https://github.com/nicholas-ruest/epoch-envelope
```

Or build from a clone:

```console
git clone https://github.com/nicholas-ruest/epoch-envelope.git
cd epoch-envelope
cargo build --release
```

## Use

Audit the included valid plan:

```console
cargo run -- --policy examples/policy.toml --plan examples/valid-plan.json
```

Request a machine-readable report:

```console
cargo run -- --policy examples/policy.toml --plan examples/valid-plan.json --format json
```

Exercise the blocked path (expected exit code `2`):

```console
cargo run -- --policy examples/policy.toml --plan examples/invalid-plan.json
```

The policy freezes accepted epoch values and resource ceilings. A plan declares global epochs, binds individual stages to those epochs, and supplies conservative per-stage estimates. `epoch-envelope` reports both the observed totals and configured limits.

## Verify

```console
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
```

## Scope and limitations

This tool audits caller-declared metadata. It does not measure a device, validate a noise model, prove statistical independence, establish quantum fault tolerance, authorize paid execution, or guarantee a scientific result. Failure probabilities are combined with a conservative union bound; correlations are not inferred. Cost units are caller-defined but must be consistent within one policy and plan. The CLI holds the parsed plan in memory and does not sign or persist reports.

## License

MIT
