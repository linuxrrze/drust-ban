//! Event times of log file lines.
//!
//! Recognized, looking only at the start of a line:
//! - ISO 8601 / RFC 3339 at the start, `2026-11-19T19:20:01.123456+01:00`
//!   (rsyslog's default on current distributions; `Z`, a space instead of
//!   `T`, and no zone = local time are accepted);
//! - classic syslog at the start, `Nov 19 19:20:01` (local time; the year
//!   is the one that puts it closest to now, so December lines read in
//!   January belong to the previous year);
//! - the common/combined log format stamp within the first 128 bytes,
//!   `[19/Nov/2026:19:20:01 +0000]`.
//!
//! Anything else: `None` (the caller uses the time it read the line).

use chrono::{DateTime, Datelike, FixedOffset, Local, NaiveDate, NaiveDateTime, TimeZone, Utc};

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

fn month(s: &str) -> Option<u32> {
    MONTHS.iter().position(|m| *m == s).map(|i| i as u32 + 1)
}

fn local(n: NaiveDateTime) -> Option<DateTime<Utc>> {
    // an hour skipped by DST: none; repeated: the earlier one
    Local
        .from_local_datetime(&n)
        .earliest()
        .map(|t| t.with_timezone(&Utc))
}

fn iso(line: &str) -> Option<DateTime<Utc>> {
    let b = line.as_bytes();
    if b.len() < 19 || b[4] != b'-' || b[7] != b'-' || !(b[10] == b'T' || b[10] == b' ') {
        return None;
    }
    // the stamp ends at the first space after the time part
    let end = line[11..].find(' ').map_or(line.len(), |i| i + 11);
    let stamp = &line[..end];
    if let Ok(t) = DateTime::parse_from_rfc3339(&stamp.replacen(' ', "T", 1)) {
        return Some(t.with_timezone(&Utc));
    }
    for f in ["%Y-%m-%dT%H:%M:%S%.f%z", "%Y-%m-%d %H:%M:%S%.f%z"] {
        if let Ok(t) = DateTime::parse_from_str(stamp, f) {
            return Some(t.with_timezone(&Utc));
        }
    }
    // no zone: local time (also "2026-11-19 19:20:01,123" from some loggers)
    let naive = stamp.replace(',', ".");
    for f in ["%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%d %H:%M:%S%.f"] {
        if let Ok(n) = NaiveDateTime::parse_from_str(&naive, f) {
            return local(n);
        }
    }
    None
}

fn syslog(line: &str, now: DateTime<Utc>) -> Option<DateTime<Utc>> {
    // "Nov 19 19:20:01" or "Nov  9 19:20:01"
    let head = line.get(..15)?;
    let m = month(head.get(..3)?)?;
    let day: u32 = head.get(4..6)?.trim_start().parse().ok()?;
    let time = chrono::NaiveTime::parse_from_str(head.get(7..15)?, "%H:%M:%S").ok()?;
    let year = now.with_timezone(&Local).year();
    // the year that puts it closest to now (Dec 31 lines read on Jan 1)
    [year - 1, year, year + 1]
        .into_iter()
        .filter_map(|y| NaiveDate::from_ymd_opt(y, m, day))
        .filter_map(|d| local(d.and_time(time)))
        .min_by_key(|t| (*t - now).num_seconds().abs())
}

fn clf(line: &str) -> Option<DateTime<Utc>> {
    let window = line.get(..line.len().min(128)).unwrap_or(line);
    let start = window.find('[')? + 1;
    // "19/Nov/2026:19:20:01 +0200]"
    let stamp = window.get(start..start + 27)?;
    if !stamp.ends_with(']') {
        return None;
    }
    DateTime::<FixedOffset>::parse_from_str(&stamp[..26], "%d/%b/%Y:%H:%M:%S %z")
        .ok()
        .map(|t| t.with_timezone(&Utc))
}

/// The event time of `line`, if it starts with a known timestamp; never
/// later than `now` (a clock running ahead must not make events last).
pub fn parse(line: &str, now: DateTime<Utc>) -> Option<DateTime<Utc>> {
    let first = *line.as_bytes().first()?;
    let t = if first.is_ascii_digit() {
        iso(line).or_else(|| clf(line))
    } else if first.is_ascii_uppercase() {
        syslog(line, now).or_else(|| clf(line))
    } else {
        clf(line)
    }?;
    Some(t.min(now))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeDelta;

    fn utc(s: &str) -> DateTime<Utc> {
        s.parse().unwrap()
    }

    #[test]
    fn formats() {
        let now = utc("2026-11-19T20:00:00Z");
        assert_eq!(
            parse("2026-11-19T19:20:01.123456+01:00 host sshd[1]: Failed", now),
            Some(utc("2026-11-19T18:20:01.123456Z"))
        );
        assert_eq!(
            parse("2026-11-19T19:20:01Z host x", now),
            Some(utc("2026-11-19T19:20:01Z"))
        );
        assert_eq!(
            parse("2026-11-19 19:20:01+0000 x", now),
            Some(utc("2026-11-19T19:20:01Z"))
        );
        assert_eq!(
            parse(
                r#"203.0.113.7 - - [19/Nov/2026:19:20:01 +0200] "GET / HTTP/1.1" 401 0"#,
                now
            ),
            Some(utc("2026-11-19T17:20:01Z"))
        );
        // local time: compare through the local zone (a day later, so no
        // zone puts it in the future)
        let now = utc("2026-11-20T20:00:00Z");
        let t = parse("2026-11-19 19:20:01,250 WARNING x", now).unwrap();
        assert_eq!(
            t.with_timezone(&Local).naive_local().to_string(),
            "2026-11-19 19:20:01.250"
        );
        let t = parse("Nov  9 19:20:01 host sshd[1]: Failed", now).unwrap();
        assert_eq!(
            t.with_timezone(&Local).naive_local().to_string(),
            "2026-11-09 19:20:01"
        );
        for no in [
            "",
            "Failed password for root",
            "x 2026-11-19T19:20:01Z",
            "Foo 19 19:20:01 x",
            "2026-13-40T99:00:00Z x",
        ] {
            assert_eq!(parse(no, now), None, "{no:?}");
        }
    }

    #[test]
    fn syslog_year_and_future() {
        // December lines read on January 1st are from last year
        let now = Local
            .with_ymd_and_hms(2027, 1, 1, 0, 5, 0)
            .unwrap()
            .with_timezone(&Utc);
        let t = parse("Dec 31 23:59:00 host x", now).unwrap();
        assert_eq!(t.with_timezone(&Local).year(), 2026);
        // never in the future
        let now = utc("2026-11-19T20:00:00Z");
        assert_eq!(parse("2026-11-19T21:00:00Z x", now), Some(now));
        assert!(now - parse("2026-11-19T19:59:00Z x", now).unwrap() == TimeDelta::minutes(1));
    }
}
