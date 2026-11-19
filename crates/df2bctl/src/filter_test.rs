//! `df2bctl filter test` – the fail2ban-regex equivalent.

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use std::path::Path;
use std::time::Instant;

use anyhow::Context;
use df2b_matcher::{Filter, FilterDef};

pub fn run(
    filter: &Path,
    log: &Path,
    show_matches: bool,
    show_missed: bool,
    json: bool,
) -> anyhow::Result<()> {
    let text =
        std::fs::read_to_string(filter).with_context(|| format!("reading {}", filter.display()))?;
    let def =
        FilterDef::from_toml(&text).with_context(|| format!("parsing {}", filter.display()))?;
    let name = filter
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let compiled = Filter::compile(name, &def)?;

    // Separate prefilter-only matcher to report "near misses".
    let prefilter = if show_missed && !def.literals.is_empty() {
        Some(def.literals.clone())
    } else {
        None
    };

    let reader = BufReader::with_capacity(
        1 << 20,
        File::open(log).with_context(|| format!("opening {}", log.display()))?,
    );
    let start = Instant::now();
    let mut total = 0u64;
    let mut matched = 0u64;
    let mut per_pattern = vec![0u64; def.failregex.len()];
    let mut per_ip: HashMap<IpAddr, u64> = HashMap::new();

    for raw in reader.split(b'\n') {
        let raw = raw?;
        let line = String::from_utf8_lossy(&raw);
        total += 1;
        match compiled.match_line(&line) {
            Some(m) => {
                matched += 1;
                per_pattern[m.pattern] += 1;
                *per_ip.entry(m.ip).or_default() += 1;
                if show_matches {
                    println!("+ {line}");
                }
            }
            None => {
                if let Some(lits) = &prefilter {
                    if lits.iter().any(|l| line.contains(l.as_str())) {
                        println!("? {line}");
                    }
                }
            }
        }
    }
    let elapsed = start.elapsed();

    let mut top: Vec<_> = per_ip.into_iter().collect();
    top.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));

    if json {
        // Hand-rolled to keep the CLI dependency-light for now.
        let ips: Vec<String> = top
            .iter()
            .map(|(ip, n)| format!("{{\"ip\":\"{ip}\",\"count\":{n}}}"))
            .collect();
        println!(
            "{{\"lines\":{total},\"matched\":{matched},\"per_pattern\":{per_pattern:?},\"elapsed_ms\":{},\"ips\":[{}]}}",
            elapsed.as_millis(),
            ips.join(",")
        );
        return Ok(());
    }

    let rate = total as f64 / elapsed.as_secs_f64().max(1e-9);
    println!("Lines:   {total} ({rate:.0} lines/s, {:.2?})", elapsed);
    println!("Matched: {matched}");
    for (i, (pattern, n)) in def.failregex.iter().zip(&per_pattern).enumerate() {
        println!("  #{i} {n:>8}  {pattern}");
    }
    println!("Distinct IPs: {}", top.len());
    for (ip, n) in top.iter().take(20) {
        println!("  {n:>8}  {ip}");
    }
    Ok(())
}
