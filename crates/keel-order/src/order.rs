//! The flat one-worker order and the reason a probe is in it.

use std::fmt;

use crate::inputs::Id;

/// Why a probe runs at all. There is no variant for likelihood, doubt or
/// budget: what runs is decided before ordering, by what changed, and the order
/// only decides when.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Selected {
    /// Its key changed since the last result that stands.
    KeyChanged,
    /// There is no result for its key.
    NoRecord,
    /// It is run again to measure flakiness, not because anything changed.
    Recheck,
    /// It failed and is run again to tell a flake from a regression.
    RerunOfFailure,
}

/// A sequence of probes that holds each probe of the run set exactly once. It
/// is the order a person reads and the order an executor without the rule
/// follows; the rule's `next` calls with one worker produce the same sequence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Order {
    units: Vec<Id>,
}

/// Why a sequence is not an [`Order`] of a run set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OrderError {
    /// A probe that must run is not in the sequence.
    Missing {
        /// The probe.
        unit: Id,
    },
    /// A probe is in the sequence more than once.
    Repeated {
        /// The probe.
        unit: Id,
    },
    /// A probe is in the sequence that is not in the run set.
    NotInRunSet {
        /// The probe.
        unit: Id,
    },
}

impl fmt::Display for OrderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OrderError::Missing { unit } => write!(
                f,
                "probe {unit} must run but is missing from the order; an order holds every probe of the run set, so rebuild it from the same plan that listed the run set"
            ),
            OrderError::Repeated { unit } => write!(
                f,
                "probe {unit} appears twice in the order; a probe runs once per run, so drop the repeat or rebuild the order from the plan"
            ),
            OrderError::NotInRunSet { unit } => write!(
                f,
                "probe {unit} is in the order but not in the run set; an order never adds a probe, so rebuild it from the plan's run set"
            ),
        }
    }
}

impl std::error::Error for OrderError {}

impl Order {
    /// The sequence `sequence` as an order of `run_set`, or an error naming the
    /// first probe that is missing, repeated, or not meant to run.
    pub fn new(run_set: &[Id], sequence: Vec<Id>) -> Result<Order, OrderError> {
        let mut wanted = run_set.to_vec();
        wanted.sort_unstable();
        wanted.dedup();
        let mut seen = vec![false; wanted.len()];
        for &u in &sequence {
            match wanted.binary_search(&u) {
                Err(_) => return Err(OrderError::NotInRunSet { unit: u }),
                Ok(i) if seen[i] => return Err(OrderError::Repeated { unit: u }),
                Ok(i) => seen[i] = true,
            }
        }
        match seen.iter().position(|&s| !s) {
            Some(i) => Err(OrderError::Missing { unit: wanted[i] }),
            None => Ok(Order { units: sequence }),
        }
    }

    /// The probes in the order they start with one worker.
    pub fn as_slice(&self) -> &[Id] {
        &self.units
    }

    /// How many probes are in the order.
    pub fn len(&self) -> usize {
        self.units.len()
    }

    /// Whether the order holds no probe.
    pub fn is_empty(&self) -> bool {
        self.units.is_empty()
    }

    /// The order as a plain vector.
    pub fn into_vec(self) -> Vec<Id> {
        self.units
    }
}
