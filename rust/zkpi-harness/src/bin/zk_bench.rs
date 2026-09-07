use zkpi_harness::zk_bench_support::{application_rows, ladder_row, primitive_costs, BACKENDS};
use zkpi_harness::{parse_value, rustc_version, write_pretty_json, HarnessResult};
use serde_json::{json, Value};
use std::ffi::OsString;
use std::path::PathBuf;

struct Options {
    sizes: Vec<usize>,
    backends: Vec<String>,
    repeats: usize,
    fast_repeats: usize,
    out: Option<PathBuf>,
}

fn main() {
    if let Err(error) = run_main() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run_main() -> HarnessResult<()> {
    let options = parse_args()?;
    let mut ladder = Vec::new();
    for backend in &options.backends {
        for &size in &options.sizes {
            let repeats = if backend == "ed25519" {
                options.fast_repeats
            } else {
                options.repeats
            };
            match ladder_row(backend, size, repeats) {
                Ok(row) => {
                    if row.get("error").is_none() {
                        println!(
                            "{backend:15} N={size:4}  prove {:8.4} ms   verify {:8.4} ms   proof {:5} B",
                            mean(&row["prove"]),
                            mean(&row["verify"]),
                            row["proof_bytes"].as_u64().unwrap_or_default(),
                        );
                    }
                    ladder.push(row);
                }
                Err(error) => {
                    ladder.push(json!({"backend": backend, "error": error.to_string()}));
                    break;
                }
            }
        }
    }

    let mut applications = Vec::new();
    for backend in ["modp_multiexp", "ed25519"] {
        if let Ok(rows) = application_rows(backend) {
            applications.extend(rows);
        }
    }
    for row in &applications {
        let cohort = row
            .get("cohort_size")
            .and_then(Value::as_u64)
            .map(|size| format!("/N={size}"))
            .unwrap_or_default();
        println!(
            "{:34} {:15} prove {:8.3} ms   verify {:8.3} ms",
            format!("{}{}", row["proof"].as_str().unwrap_or_default(), cohort),
            row["backend"].as_str().unwrap_or_default(),
            mean(&row["prove"]),
            mean(&row["verify"]),
        );
    }

    let payload = json!({
        "host": zkfmi_measure::hosts::this_host(),
        "rustc": rustc_version(),
        "machine": machine(),
        "primitives": primitive_costs(),
        "ladder": ladder,
        "applications": applications,
    });
    if let Some(path) = options.out.as_deref() {
        write_pretty_json(Some(path), &payload)?;
        println!("wrote {}", path.display());
    }
    Ok(())
}

fn mean(summary: &Value) -> f64 {
    summary["mean"].as_f64().unwrap_or_default()
}

fn machine() -> String {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => "arm64".to_string(),
        (_, architecture) => architecture.to_string(),
    }
}

fn parse_args() -> HarnessResult<Options> {
    let mut options = Options {
        sizes: vec![8, 32, 128],
        backends: BACKENDS.iter().map(ToString::to_string).collect(),
        repeats: 5,
        fast_repeats: 200,
        out: None,
    };
    let mut args = std::env::args_os().skip(1).peekable();
    while let Some(argument) = args.next() {
        match argument.to_str() {
            Some("--sizes") => options.sizes = parse_many(&mut args, "--sizes")?,
            Some("--backends") => options.backends = parse_many_strings(&mut args, "--backends")?,
            Some("--repeats") => {
                options.repeats = parse_value(next(&mut args, "--repeats")?, "--repeats")?
            }
            Some("--fast-repeats") => {
                options.fast_repeats =
                    parse_value(next(&mut args, "--fast-repeats")?, "--fast-repeats")?
            }
            Some("--out") => options.out = Some(PathBuf::from(next(&mut args, "--out")?)),
            Some("-h" | "--help") => {
                println!(
                    "usage: zk_bench [--sizes N ...] [--backends NAME ...] \
                     [--repeats N] [--fast-repeats N] [--out PATH]"
                );
                std::process::exit(0);
            }
            Some(value) => return Err(format!("unrecognised argument {value}").into()),
            None => return Err("argument is not valid UTF-8".into()),
        }
    }
    if options.sizes.is_empty()
        || options.sizes.contains(&0)
        || options.backends.is_empty()
        || options.repeats == 0
        || options.fast_repeats == 0
    {
        return Err("sizes, backends, and repeat counts must be non-empty and positive".into());
    }
    Ok(options)
}

fn next(
    args: &mut std::iter::Peekable<impl Iterator<Item = OsString>>,
    name: &str,
) -> HarnessResult<OsString> {
    args.next()
        .ok_or_else(|| format!("argument {name} expects one value").into())
}

fn parse_many(
    args: &mut std::iter::Peekable<impl Iterator<Item = OsString>>,
    name: &str,
) -> HarnessResult<Vec<usize>> {
    let mut values = Vec::new();
    while args
        .peek()
        .and_then(|value| value.to_str())
        .is_some_and(|value| !value.starts_with("--"))
    {
        values.push(parse_value(next(args, name)?, name)?);
    }
    if values.is_empty() {
        return Err(format!("argument {name} expects at least one value").into());
    }
    Ok(values)
}

fn parse_many_strings(
    args: &mut std::iter::Peekable<impl Iterator<Item = OsString>>,
    name: &str,
) -> HarnessResult<Vec<String>> {
    let mut values = Vec::new();
    while args
        .peek()
        .and_then(|value| value.to_str())
        .is_some_and(|value| !value.starts_with("--"))
    {
        values.push(
            next(args, name)?
                .into_string()
                .map_err(|_| format!("argument {name} is not valid UTF-8"))?,
        );
    }
    if values.is_empty() {
        return Err(format!("argument {name} expects at least one value").into());
    }
    Ok(values)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn machine_matches_the_versioned_platform_contract() {
        let expected = match (std::env::consts::OS, std::env::consts::ARCH) {
            ("macos", "aarch64") => "arm64",
            ("macos", "x86_64") | ("linux", "x86_64") => "x86_64",
            ("linux", "aarch64") => "aarch64",
            (system, architecture) => {
                panic!("versioned platform contract has no {system}/{architecture} entry")
            }
        };
        assert_eq!(machine(), expected);
    }
}
