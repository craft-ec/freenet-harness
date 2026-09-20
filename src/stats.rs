//! Percentiles and table formatting for measured samples.
//!
//! Kept free of I/O and of the node so it can be unit-tested: a latency table
//! nobody can check is a table nobody should believe.

use std::fmt::Write as _;

/// Nearest-rank percentile of an already-sorted, non-empty slice.
///
/// Nearest rank, not interpolation: every printed number is a sample that was
/// actually observed, so "p99 = 812 ms" names a put that really took 812 ms.
fn nearest_rank(sorted: &[f64], pct: f64) -> f64 {
    debug_assert!(!sorted.is_empty());
    let n = sorted.len() as f64;
    let rank = (pct / 100.0 * n).ceil().max(1.0) as usize;
    sorted[rank.min(sorted.len()) - 1]
}

/// The five numbers reported for one measured series, in milliseconds.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Summary {
    pub n: usize,
    pub min: f64,
    pub p50: f64,
    pub p90: f64,
    pub p99: f64,
    pub max: f64,
}

impl Summary {
    /// `None` for an empty series — no samples is not a latency of zero.
    pub fn of(samples: &[f64]) -> Option<Self> {
        if samples.is_empty() {
            return None;
        }
        let mut s = samples.to_vec();
        s.sort_by(|a, b| a.partial_cmp(b).expect("latency samples are never NaN"));
        Some(Summary {
            n: s.len(),
            min: s[0],
            p50: nearest_rank(&s, 50.0),
            p90: nearest_rank(&s, 90.0),
            p99: nearest_rank(&s, 99.0),
            max: s[s.len() - 1],
        })
    }

    /// The five numbers as table cells, in the order of [`Summary::HEADINGS`].
    pub fn cells(&self) -> Vec<String> {
        [self.min, self.p50, self.p90, self.p99, self.max]
            .iter()
            .map(|v| format!("{v:.1}"))
            .collect()
    }

    pub const HEADINGS: [&'static str; 5] = ["min", "p50", "p90", "p99", "max"];
}

/// A left-aligned first column, right-aligned numbers — the shape every table
/// in this harness prints.
pub struct Table {
    headings: Vec<String>,
    rows: Vec<Vec<String>>,
}

impl Table {
    pub fn new<S: Into<String>>(headings: impl IntoIterator<Item = S>) -> Self {
        Table {
            headings: headings.into_iter().map(Into::into).collect(),
            rows: Vec::new(),
        }
    }

    pub fn row<S: Into<String>>(&mut self, cells: impl IntoIterator<Item = S>) {
        self.rows.push(cells.into_iter().map(Into::into).collect());
    }

    /// Column widths from the widest cell, so a table stays readable whatever
    /// the numbers turn out to be.
    fn widths(&self) -> Vec<usize> {
        let mut w: Vec<usize> = self.headings.iter().map(|h| h.chars().count()).collect();
        for r in &self.rows {
            for (i, c) in r.iter().enumerate() {
                if i < w.len() {
                    w[i] = w[i].max(c.chars().count());
                }
            }
        }
        w
    }
}

impl std::fmt::Display for Table {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let w = self.widths();
        let mut line = String::new();
        for (i, h) in self.headings.iter().enumerate() {
            let _ = if i == 0 {
                write!(line, "{:<width$}", h, width = w[i])
            } else {
                write!(line, "  {:>width$}", h, width = w[i])
            };
        }
        writeln!(f, "{line}")?;
        writeln!(f, "{}", "-".repeat(line.chars().count()))?;
        for r in &self.rows {
            let mut line = String::new();
            for (i, c) in r.iter().enumerate() {
                let width = w.get(i).copied().unwrap_or(0);
                let _ = if i == 0 {
                    write!(line, "{c:<width$}")
                } else {
                    write!(line, "  {c:>width$}")
                };
            }
            writeln!(f, "{line}")?;
        }
        Ok(())
    }
}

/// The resolution of a polling instrument, and whether a series cleared it.
///
/// Every "when did this become readable" number in this harness comes from
/// asking, waiting one attempt, and asking again. That gives the instrument a
/// PERIOD, and a series whose whole spread fits inside one period was measured
/// by the instrument rather than by the node — it says "not on that pass, yes
/// on the next" and nothing finer. This has now been the cause of two withdrawn
/// tables, so it is a type rather than a habit: any subcommand that polls
/// builds one of these, prints it, and asks it about every series before the
/// numbers are believed.
#[derive(Clone, Copy, Debug)]
pub struct Grid {
    /// One attempt plus the pause before the next, in milliseconds.
    pub ms: f64,
}

impl Grid {
    pub fn new(attempt_ms: f64, gap_ms: f64) -> Self {
        Grid {
            ms: attempt_ms + gap_ms,
        }
    }

    /// The line that goes above any table this instrument produced.
    pub fn line(&self) -> String {
        format!(
            "resolution: {:.0} ms — this instrument asks, waits one attempt, and asks again, \
             so nothing finer than that is resolved",
            self.ms
        )
    }

    /// `Some(reason)` when `label`'s numbers are the instrument's own period.
    ///
    /// Two conditions, and both are needed. The spread must fit inside one step
    /// — a series that varies by more than a step is resolving something. And
    /// the minimum must be ABOVE one step, because a series that came back on
    /// its first pass was not waiting for the grid at all, and flagging it
    /// would cry wolf on exactly the fast case.
    pub fn unresolved(&self, label: &str, s: &Summary) -> Option<String> {
        (s.max - s.min < self.ms && s.min > self.ms).then(|| {
            format!(
                "{label}: every sample landed between {:.0} and {:.0} ms, inside one {:.0} ms step \
                 — that says \"not on that pass, yes on the next\" and nothing finer",
                s.min, s.max, self.ms
            )
        })
    }
}

/// `16384` → `16 KiB`, for table labels.
pub fn kib(bytes: usize) -> String {
    if bytes >= 1024 && bytes.is_multiple_of(1024) {
        format!("{} KiB", bytes / 1024)
    } else {
        format!("{bytes} B")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 1..=100 makes every percentile readable by eye: nearest rank on a
    /// hundred samples puts pN exactly on the sample numbered N.
    #[test]
    fn percentiles_are_observed_samples() {
        let s: Vec<f64> = (1..=100).map(|i| i as f64).collect();
        let r = Summary::of(&s).unwrap();
        assert_eq!(r.n, 100);
        assert_eq!(r.min, 1.0);
        assert_eq!(r.p50, 50.0);
        assert_eq!(r.p90, 90.0);
        assert_eq!(r.p99, 99.0);
        assert_eq!(r.max, 100.0);
    }

    /// Unsorted input must give the same answer as sorted input.
    #[test]
    fn order_does_not_matter() {
        let asc: Vec<f64> = (1..=30).map(|i| i as f64).collect();
        let mut shuffled = asc.clone();
        shuffled.reverse();
        shuffled.swap(0, 17);
        assert_eq!(Summary::of(&asc), Summary::of(&shuffled));
    }

    /// With 30 samples the rank for p99 rounds up to the last one; that is the
    /// honest answer, not an interpolated number nobody measured.
    #[test]
    fn thirty_samples_put_p99_on_the_maximum() {
        let s: Vec<f64> = (1..=30).map(|i| i as f64).collect();
        let r = Summary::of(&s).unwrap();
        assert_eq!(r.p99, 30.0);
        assert_eq!(r.p90, 27.0);
    }

    #[test]
    fn one_sample_is_every_percentile() {
        let r = Summary::of(&[7.5]).unwrap();
        assert_eq!(
            (r.min, r.p50, r.p90, r.p99, r.max),
            (7.5, 7.5, 7.5, 7.5, 7.5)
        );
    }

    /// No samples is not a latency of zero.
    #[test]
    fn empty_has_no_summary() {
        assert!(Summary::of(&[]).is_none());
    }

    /// The flag must fire on the case that caused it and stay quiet on the
    /// case that looks similar and is not. Both halves, because a flag that is
    /// always on is ignored as fast as one that is never on.
    #[test]
    fn the_grid_flags_its_own_period_and_nothing_else() {
        let g = Grid::new(400.0, 25.0);
        // The real one: ten trials from 433.8 to 476.3 on a 425 ms grid.
        let stuck = Summary::of(&[433.8, 435.0, 440.1, 452.0, 476.3]).unwrap();
        assert!(g.unresolved("1x", &stuck).is_some());
        // Spread wider than a step: something is being resolved.
        let spread = Summary::of(&[430.0, 900.0, 1500.0, 2600.0]).unwrap();
        assert!(g.unresolved("1x", &spread).is_none());
        // Back on the first pass: never waited for the grid at all.
        let fast = Summary::of(&[120.0, 145.0, 160.0, 184.0]).unwrap();
        assert!(g.unresolved("4x", &fast).is_none());
        // A finer grid resolves a series the coarse one could not. These
        // samples span three 70 ms steps and sit inside one 425 ms step.
        let spans = Summary::of(&[433.8, 520.0, 610.0]).unwrap();
        assert!(
            g.unresolved("1x", &spans).is_some(),
            "425 ms cannot resolve this"
        );
        assert!(Grid::new(60.0, 10.0).unresolved("1x", &spans).is_none());
        // And a series that is genuinely inside one step stays flagged however
        // fine the grid is, because it genuinely is inside one step.
        assert!(Grid::new(60.0, 10.0).unresolved("1x", &stuck).is_some());
    }

    #[test]
    fn sizes_read_as_kib() {
        assert_eq!(kib(1024), "1 KiB");
        assert_eq!(kib(262144), "256 KiB");
        assert_eq!(kib(100), "100 B");
        assert_eq!(kib(1500), "1500 B");
    }

    #[test]
    fn table_aligns_to_its_widest_cell() {
        let mut t = Table::new(["kind", "min"]);
        t.row(["Block", "1.0"]);
        t.row(["a-very-long-kind", "1234.5"]);
        let out = t.to_string();
        let width = out.lines().next().unwrap().chars().count();
        // Every line, including the rule, is the same width.
        for l in out.lines() {
            assert_eq!(l.chars().count(), width, "ragged line: {l:?}");
        }
    }
}
