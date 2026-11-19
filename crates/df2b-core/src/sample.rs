//! Sample log lines sent with observations (DESIGN.md §4.1).

/// Longest sample kept, in bytes.
pub const MAX_SAMPLE: usize = 512;

/// A log line made safe to send, store and show: control characters
/// (also escape sequences, CR) become spaces, surrounding whitespace is
/// trimmed and the result is cut to `MAX_SAMPLE` bytes at a character
/// boundary (marked with "…").
pub fn sample_line(line: &str) -> String {
    let clean: String = line
        .trim()
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if clean.len() <= MAX_SAMPLE {
        return clean;
    }
    let mut end = MAX_SAMPLE - '…'.len_utf8();
    while !clean.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &clean[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cleaned_and_bounded() {
        assert_eq!(
            sample_line("  Failed password\tfor root\r\n"),
            "Failed password for root"
        );
        assert_eq!(sample_line("a\u{1b}[31mred"), "a [31mred");
        let long = "ä".repeat(400); // 800 bytes
        let s = sample_line(&long);
        assert!(s.len() <= MAX_SAMPLE && s.ends_with('…'), "{}", s.len());
        assert!(s.starts_with("ää"));
    }
}
