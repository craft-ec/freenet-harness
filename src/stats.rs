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
