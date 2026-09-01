//! The evaluation command.
//!
//! ```text
//! kern-eval run     --scenarios evaluation/scenarios --out evaluation/results/deterministic.jsonl
//! kern-eval report  --in evaluation/results --out evaluation/reports
//! kern-eval check   --in evaluation/results
//! ```
//!
//! # Exit status
//!
//! ```text
//! 0   every record ran and no invariant was violated
//! 1   at least one invariant violation, or an expectation that did not hold
//! 2   the harness itself could not run
//! ```
//!
//! Status 1 and status 2 are deliberately different. A harness that cannot read
//! its scenario directory has not falsified anything about Kern, and reporting
//! that as a security failure would train everybody to ignore the exit code.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use kern_eval::record::Mode;
use kern_eval::report;
use kern_eval::runner::RunConfig;
use kern_eval::scenario;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = args.first().map(String::as_str).unwrap_or("run");

    match command {
        "run" => run(&args),
        "report" => report_command(&args),
        "check" => check(&args),
        "help" | "--help" | "-h" => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        other => {
            eprintln!("unknown command `{other}`\n\n{USAGE}");
            ExitCode::from(2)
        }
    }
}

const USAGE: &str = "\
kern-eval — the Kern adversarial evaluation harness

  kern-eval run     [--scenarios DIR] [--out FILE] [--run-id ID]
  kern-eval report  [--in DIR_OR_FILE] [--out DIR]
  kern-eval check   [--in DIR_OR_FILE]

Measures authority containment. Not robot safety.";

fn option(args: &[String], name: &str, default: &str) -> String {
    args.windows(2)
        .find(|pair| pair[0] == name)
        .map(|pair| pair[1].clone())
        .unwrap_or_else(|| default.to_string())
}

/// Runs every deterministic scenario and writes one JSONL record each.
fn run(args: &[String]) -> ExitCode {
    let dir = option(args, "--scenarios", "evaluation/scenarios");
    let out = option(args, "--out", "evaluation/results/deterministic.jsonl");
    let run_id = option(args, "--run-id", "deterministic");

    let scenarios = match scenario::load_dir(&dir) {
        Ok(scenarios) => scenarios,
        Err(error) => {
            eprintln!("could not load scenarios: {error}");
            return ExitCode::from(2);
        }
    };

    let config = RunConfig {
        run_id,
        mode: Mode::Deterministic,
        git_revision: kern_eval::git_revision(),
        // Nothing in a deterministic run is random, so there is no seed to
        // record. Recording one anyway would imply a knob that does not exist.
        seed: None,
    };

    let runnable: Vec<_> = scenarios
        .iter()
        .filter(|scenario| !scenario.live_only)
        .collect();
    println!(
        "loaded {} scenarios ({} deterministic, {} live-only and skipped)",
        scenarios.len(),
        runnable.len(),
        scenarios.len() - runnable.len()
    );

    if let Some(parent) = Path::new(&out).parent() {
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

    let mut violations = 0u64;
    let mut expectation_failures = 0u64;
    for scenario in runnable {
        let record = kern_eval::run_scenario(&config, scenario);
        violations += record.violations.len() as u64;
        if record.expectation_met == Some(false) {
            expectation_failures += 1;
            eprintln!(
                "expectation did not hold: {} (expected {})",
                record.scenario_id, record.expectation
            );
        }
        for violation in &record.violations {
            eprintln!(
                "INVARIANT VIOLATION: {} in {}",
                violation, record.scenario_id
            );
        }
        if let Err(error) = writeln!(writer, "{}", record.to_json()) {
            eprintln!("could not write a record: {error}");
            return ExitCode::from(2);
        }
    }
    if let Err(error) = writer.flush() {
        eprintln!("could not flush {out}: {error}");
        return ExitCode::from(2);
    }

    println!("wrote {out}");
    println!("invariant violations: {violations}");
    println!("expectations that did not hold: {expectation_failures}");

    if violations > 0 || expectation_failures > 0 {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

/// Aggregates records into the summary artifacts.
fn report_command(args: &[String]) -> ExitCode {
    let input = option(args, "--in", "evaluation/results");
    let out = option(args, "--out", "evaluation/reports");

    let records = match load(&input) {
        Ok(records) => records,
        Err(code) => return code,
    };
    let summary = report::summarize(&records);

    if let Err(error) = std::fs::create_dir_all(&out) {
        eprintln!("could not create {out}: {error}");
        return ExitCode::from(2);
    }
    let json_path = PathBuf::from(&out).join("summary.json");
    let md_path = PathBuf::from(&out).join("summary.md");
    let csv_path = PathBuf::from(&out).join("latencies.csv");

    if let Err(error) = std::fs::write(&json_path, format!("{}\n", summary.to_json())) {
        eprintln!("could not write {}: {error}", json_path.display());
        return ExitCode::from(2);
    }
    if let Err(error) = std::fs::write(&md_path, summary.to_markdown()) {
        eprintln!("could not write {}: {error}", md_path.display());
        return ExitCode::from(2);
    }
    if let Err(error) = std::fs::write(&csv_path, latencies_csv(&records)) {
        eprintln!("could not write {}: {error}", csv_path.display());
        return ExitCode::from(2);
    }

    println!("wrote {}", json_path.display());
    println!("wrote {}", md_path.display());
    println!("wrote {}", csv_path.display());
    println!("{}", summary.containment.render());

    if summary.violation_total > 0 {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

/// Re-checks stored records without re-running anything.
fn check(args: &[String]) -> ExitCode {
    let input = option(args, "--in", "evaluation/results");
    let records = match load(&input) {
        Ok(records) => records,
        Err(code) => return code,
    };
    let summary = report::summarize(&records);

    println!("records: {}", summary.total);
    println!("authority containment: {}", summary.containment.render());
    println!(
        "parser containment:    {}",
        summary.parser_containment.render()
    );
    println!("invariant violations:  {}", summary.violation_total);

    if summary.violation_total > 0 {
        for (violation, count) in &summary.violations {
            if *count > 0 {
                eprintln!("INVARIANT VIOLATION: {violation} x{count}");
            }
        }
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

fn load(input: &str) -> Result<Vec<report::LoadedRecord>, ExitCode> {
    let path = Path::new(input);
    let mut files: Vec<PathBuf> = if path.is_dir() {
        let mut found: Vec<PathBuf> = match std::fs::read_dir(path) {
            Ok(entries) => entries
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .filter(|path| path.extension().is_some_and(|ext| ext == "jsonl"))
                .collect(),
            Err(error) => {
                eprintln!("could not read {input}: {error}");
                return Err(ExitCode::from(2));
            }
        };
        found.sort();
        found
    } else {
        vec![path.to_path_buf()]
    };
    files.sort();

    let mut records = Vec::new();
    for file in files {
        match report::load_jsonl(&file) {
            Ok(loaded) => records.extend(loaded),
            Err(error) => {
                eprintln!("could not read records: {error}");
                return Err(ExitCode::from(2));
            }
        }
    }
    if records.is_empty() {
        eprintln!("no records found under {input}");
        return Err(ExitCode::from(2));
    }
    Ok(records)
}

/// One row per observed latency, so the numbers in the summary can be checked.
fn latencies_csv(records: &[report::LoadedRecord]) -> String {
    let mut out = String::from(
        "scenario_id,category,mode,lapse_latency_ms,cancel_request_latency_ms,cancel_confirm_latency_ms\n",
    );
    for record in records {
        if record.lapse_latency_ms.is_none()
            && record.cancel_request_latency_ms.is_none()
            && record.cancel_confirm_latency_ms.is_none()
        {
            continue;
        }
        let cell = |value: Option<i64>| value.map_or(String::new(), |value| value.to_string());
        out.push_str(&format!(
            "{},{},{},{},{},{}\n",
            record.scenario_id,
            record.category,
            record.mode,
            cell(record.lapse_latency_ms),
            cell(record.cancel_request_latency_ms),
            cell(record.cancel_confirm_latency_ms),
        ));
    }
    out
}
