//! Mode B, part one: the same evaluation, driven by a live model.
//!
//! ```text
//! kern-eval-live [--scenarios DIR] [--out FILE] [--repeats N]
//! ```
//!
//! It loads the same scenario packs, keeps the ones marked `live_only`, and
//! runs each through [`kern_eval::runner::run_with_model`] — the identical
//! function the deterministic runner uses, with a gateway behind the
//! `ProposalModel` boundary instead of a fixture. The records it writes have the
//! same schema, and the same aggregator reads them.
//!
//! # What is and is not reproducible
//!
//! Records from here are marked `reproducible: false`. A language model's output
//! is not deterministic, and re-running this will not reproduce the same bytes.
//! What *is* reproducible is everything below the trust boundary: the same
//! normalized proposal always produces the same decision, whoever proposed it.
//!
//! # The result is not whether the model behaved
//!
//! A model that refuses a hostile instruction has told us nothing about Kern. A
//! model that obeys one, produces an unauthorized proposal, and is contained is
//! the useful observation. Both are recorded exactly as they happened.

use std::io::Write as _;
use std::process::ExitCode;

use kern_eval::record::Mode;
use kern_eval::runner::{run_with_model, RunConfig};
use kern_eval::scenario;
use kern_model_openai_compatible::{load_dotenv, GatewayConfig, GatewayModel};

fn main() -> ExitCode {
    if let Some(path) = load_dotenv(std::env::current_dir().unwrap_or_default()) {
        eprintln!("loaded environment from {}", path.display());
    }

    let args: Vec<String> = std::env::args().skip(1).collect();
    let dir = option(&args, "--scenarios", "evaluation/scenarios");
    let out = option(&args, "--out", "evaluation/results/live.jsonl");
    let repeats: usize = option(&args, "--repeats", "1").parse().unwrap_or(1);

    let config = match GatewayConfig::from_env() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("configuration error: {error}");
            eprintln!("LIVE EVALUATION NOT RUN — no live model was called.");
            return ExitCode::from(2);
        }
    };
    println!("provider: {}", config.provider());
    println!("base URL: {}", config.base_url());
    println!("model:    {}", config.model());

    let scenarios = match scenario::load_dir(&dir) {
        Ok(scenarios) => scenarios,
        Err(error) => {
            eprintln!("could not load scenarios: {error}");
            return ExitCode::from(2);
        }
    };
    let live: Vec<_> = scenarios
        .iter()
        .filter(|scenario| scenario.live_only)
        .collect();
    if live.is_empty() {
        eprintln!("no live scenarios found under {dir}");
        return ExitCode::from(2);
    }
    println!("live scenarios: {} x {repeats} repeat(s)\n", live.len());

    if let Some(parent) = std::path::Path::new(&out).parent() {
        if let Err(error) = std::fs::create_dir_all(parent) {
            eprintln!("could not create {}: {error}", parent.display());
            return ExitCode::from(2);
        }
    }
    let file = match std::fs::File::create(&out) {
        Ok(file) => file,
        Err(error) => {
            eprintln!("could not write {out}: {error}");
            return ExitCode::from(2);
        }
    };
    let mut writer = std::io::BufWriter::new(file);

    let run_config = RunConfig {
        run_id: format!("live-{}", config.model()),
        mode: Mode::Live,
        git_revision: kern_eval::git_revision(),
        // A live model has no seed anybody controls. Saying `null` is the
        // honest answer; inventing one would imply reproducibility.
        seed: None,
    };

    let mut violations = 0u64;
    for repeat in 0..repeats.max(1) {
        for scenario in &live {
            // A fresh client per scenario, so one wedged connection cannot make
            // the rest of the suite look like a model failure.
            let model = GatewayModel::new(config.clone());
            let mut record = run_with_model(&run_config, scenario, model);
            if repeats > 1 {
                record.scenario_id = format!("{}#repeat={repeat}", record.scenario_id);
            }
            report(&record);
            violations += record.violations.len() as u64;
            for violation in &record.violations {
                eprintln!("INVARIANT VIOLATION: {violation} in {}", record.scenario_id);
            }
            if let Err(error) = writeln!(writer, "{}", record.to_json()) {
                eprintln!("could not write a record: {error}");
                return ExitCode::from(2);
            }
        }
    }
    if let Err(error) = writer.flush() {
        eprintln!("could not flush {out}: {error}");
        return ExitCode::from(2);
    }

    println!("\nwrote {out}");
    println!("invariant violations: {violations}");
    if violations > 0 {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

/// One line per scenario, showing where the pipeline stopped.
fn report(record: &kern_eval::ExperimentRecord) {
    let field = |value: &Option<String>| value.clone().unwrap_or_else(|| String::from("—"));
    println!("{}", record.scenario_id);
    println!("  instruction: {}", record.description);
    println!(
        "  parse={} normalize={} policy={} stage={}",
        field(&record.proposal.parse),
        field(&record.proposal.normalization),
        field(&record.proposal.policy),
        record.proposal.stage
    );
    if let Some(arguments) = &record.proposal.arguments {
        println!("  proposal:    {arguments}");
    }
    if let Some(detail) = &record.proposal.detail {
        println!("  detail:      {detail}");
    }
    println!(
        "  authority={} execution={} invoked={}",
        if record.authority.created {
            field(&record.authority.artifact_id)
        } else {
            String::from("NONE")
        },
        field(&record.execution.state),
        record.execution.executor_invoked
    );
    println!();
}

fn option(args: &[String], name: &str, default: &str) -> String {
    args.windows(2)
        .find(|pair| pair[0] == name)
        .map(|pair| pair[1].clone())
        .unwrap_or_else(|| default.to_string())
}
