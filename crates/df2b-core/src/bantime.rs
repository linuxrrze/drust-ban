//! Escalating ban durations for repeat offenders.

use std::time::Duration;

/// `base × factor^(offense-1)`, capped at `max`.
///
/// `offense` is 1 for the first ban. A `factor` below 1.0 is treated as 1.0.
pub fn escalated_bantime(
    base: Duration,
    factor: f64,
    max: Option<Duration>,
    offense: u32,
) -> Duration {
    let exp = offense.saturating_sub(1).min(64) as i32;
    let secs = base.as_secs_f64() * factor.max(1.0).powi(exp);
    let d = if secs.is_finite() && secs < 1e15 {
        Duration::from_secs_f64(secs)
    } else {
        Duration::MAX
    };
    match max {
        Some(m) => d.min(m),
        None => d,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const H: Duration = Duration::from_secs(3600);

    #[test]
    fn escalates_and_caps() {
        assert_eq!(escalated_bantime(H, 2.0, None, 1), H);
        assert_eq!(escalated_bantime(H, 2.0, None, 3), 4 * H);
        assert_eq!(escalated_bantime(H, 2.0, Some(3 * H), 3), 3 * H);
        assert_eq!(escalated_bantime(H, 2.0, None, 1000), Duration::MAX);
    }

    #[test]
    fn factor_below_one_is_constant() {
        assert_eq!(escalated_bantime(H, 0.5, None, 5), H);
    }
}
