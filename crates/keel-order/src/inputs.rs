//! The file the planner writes and the executor reads: what the rule is told.
//!
//! The rule never sees nodes, names or results. It sees positions: a probe is
//! `0..units`, a set-up is `0..steps`, a fault class is `0..class_mass.len()`.

use std::fmt;

/// A probe's position in the order's unit list, `0..DoubtInputs::units`.
pub type Id = u32;

/// A set-up step's position, `0..DoubtInputs::steps`: a build, a link, a boot
/// of a world, or a gate probe that other probes wait for.
pub type StepIx = u32;

/// The content digest of the plan the positions index into. The rule only
/// carries it so a stored file can be matched to its plan; it never reads it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Digest(pub [u8; 32]);

/// A duration in milliseconds.
#[derive(Clone, Copy, Debug, PartialEq, PartialOrd)]
pub struct Millis(pub f64);

/// A number with the provenance the plan keeps for it. The rule uses only the
/// value, because it uses costs to order and to nothing else; the provenance
/// stays so the file round-trips what the plan said.
#[derive(Clone, Debug, PartialEq)]
pub enum Number<T> {
    /// Taken from stored records.
    Measured {
        /// The value.
        value: T,
        /// How many records it was taken from.
        samples: u32,
        /// Digest of the records.
        from: Digest,
    },
    /// An upper or derived figure with the name of the rule that made it.
    Bound {
        /// The value.
        value: T,
        /// The rule that produced it.
        rule: &'static str,
    },
    /// A stand-in that is good enough to order by and must never be printed.
    Placeholder {
        /// The value.
        value: T,
    },
}

impl Number<Millis> {
    /// The duration in milliseconds, whatever its provenance.
    pub fn millis(&self) -> f64 {
        match self {
            Number::Measured { value, .. }
            | Number::Bound { value, .. }
            | Number::Placeholder { value } => value.0,
        }
    }
}

/// Rows of variable length in two flat vectors: row `i` is
/// `items[offsets[i]..offsets[i + 1]]`.
#[derive(Clone, Debug, PartialEq)]
pub struct Csr<T> {
    /// `rows + 1` ascending positions into `items`; the first is 0.
    pub offsets: Vec<u32>,
    /// All rows, one after the other.
    pub items: Vec<T>,
}

impl<T> Default for Csr<T> {
    fn default() -> Self {
        Csr {
            offsets: vec![0],
            items: Vec::new(),
        }
    }
}

impl<T> Csr<T> {
    /// Builds the table from rows.
    ///
    /// # Panics
    /// If the rows hold more than `u32::MAX` items together: the offsets are 4
    /// bytes each so that a table of 10^6 entries stays small, and a table that
    /// big is a planner bug to be named, not wrapped.
    pub fn from_rows(rows: impl IntoIterator<Item = Vec<T>>) -> Csr<T> {
        let mut csr = Csr::default();
        for row in rows {
            csr.items.extend(row);
            let end = u32::try_from(csr.items.len())
                .expect("a Csr holds at most u32::MAX items; split the table or widen the offsets in keel-order");
            csr.offsets.push(end);
        }
        csr
    }

    /// How many rows there are.
    pub fn rows(&self) -> usize {
        self.offsets.len().saturating_sub(1)
    }

    /// Row `i`.
    ///
    /// # Panics
    /// If `i` is not a row.
    pub fn row(&self, i: usize) -> &[T] {
        &self.items[self.offsets[i] as usize..self.offsets[i + 1] as usize]
    }
}

/// Everything the rule needs to order one change's probes.
///
/// A probe is the unit of running; a *fault class* is a set of faults that the
/// same probes detect; a probe's *kill* `(class, q)` says that if the class is
/// present the probe fails with probability `q`. The mass of a class is how
/// likely it is that the change carries it.
#[derive(Clone, Debug, PartialEq)]
pub struct DoubtInputs {
    /// The plan these positions index into.
    pub plan: Digest,
    /// How many probes there are; every per-unit table below has this many rows.
    pub units: u32,
    /// How many set-up steps there are; every per-step table has this many rows.
    pub steps: u32,
    /// The prior chance mass of each fault class of the change (the unit's prior
    /// times the class's share). A class no probe kills is a constant and
    /// changes no order.
    pub class_mass: Vec<f32>,
    /// Per probe, the classes it detects and with what probability `q` in
    /// (0, 1], ascending by class with no class twice.
    pub kills: Csr<(u32, f32)>,
    /// Per probe, what one run costs. Positive: a free probe has infinite
    /// density and the rule would run it first for no reason.
    pub cost_ms: Vec<Number<Millis>>,
    /// Per probe, the steps that must be up before it can start: its link
    /// step, its world, and the gate steps of the probes it waits for.
    pub needs: Csr<StepIx>,
    /// Per step, what bringing it up costs, paid once. Ignored for a gate
    /// step, whose price is the run cost of its gate probe.
    pub setup_ms: Vec<Number<Millis>>,
    /// Per probe, how many atoms it reaches. Among equals the probe that
    /// reaches fewer goes first because it localises a failure better.
    pub reach: Vec<u32>,
    /// Per probe, the step it is the gate of, if any. A gate probe is a check
    /// that other probes (its twins) wait for: it is a probe with a gain of its
    /// own, and its step comes up only when the executor reports that it
    /// passed. Empty means no gates. The file is refused, naming the probe, if two
    /// probes are the gate of one step ([`InputsError::GateStepTaken`]), if a probe
    /// waits for gates that are not one chain ([`InputsError::GatesJoin`]), or if a
    /// probe behind a gate needs a build or world its gate does not
    /// ([`InputsError::ChildSetupDiffers`]). A gate step's `setup_ms` is not read:
    /// its price is its probe's run cost.
    pub gate_of: Vec<Option<StepIx>>,
}

/// Why a [`DoubtInputs`] cannot be ordered. Every message says what is wrong,
/// what it stands on, and what to change in the planner.
#[derive(Clone, Debug, PartialEq)]
pub enum InputsError {
    /// A table has the wrong number of rows for the counts the file declares.
    Count {
        /// The table.
        table: &'static str,
        /// Rows it has.
        found: usize,
        /// Rows its count declares.
        expected: usize,
    },
    /// A class number is not below `class_mass.len()`.
    ClassOutOfRange {
        /// The probe whose kill row names it.
        unit: Id,
        /// The class.
        class: u32,
        /// How many classes there are.
        classes: usize,
    },
    /// A kill row is not strictly ascending by class.
    ClassesNotAscending {
        /// The probe.
        unit: Id,
    },
    /// A kill probability outside (0, 1], or not a number.
    BadKill {
        /// The probe.
        unit: Id,
        /// The class.
        class: u32,
        /// The probability.
        q: f32,
    },
    /// A class mass that is negative or not finite.
    BadMass {
        /// The class.
        class: u32,
        /// The mass.
        mass: f32,
    },
    /// A probe cost that is not positive and finite.
    BadCost {
        /// The probe.
        unit: Id,
        /// The cost in milliseconds.
        ms: f64,
    },
    /// A set-up cost that is negative or not finite.
    BadSetup {
        /// The step.
        step: StepIx,
        /// The cost in milliseconds.
        ms: f64,
    },
    /// A step number is not below `steps`.
    StepOutOfRange {
        /// The table that names it.
        table: &'static str,
        /// The probe whose row names it.
        unit: Id,
        /// The step.
        step: StepIx,
        /// How many steps there are.
        steps: u32,
    },
    /// Two probes claim to be the gate of the same step.
    GateStepTaken {
        /// The step.
        step: StepIx,
        /// The first probe that claims it.
        first: Id,
        /// The second.
        second: Id,
    },
    /// A probe waits for gate steps that are not one chain: it needs two gates
    /// neither of which waits for the other, or a gate waits for itself. The
    /// rule orders forests of gates; two unrelated probes that must both pass
    /// first is the general case with no bound.
    GatesJoin {
        /// The probe.
        unit: Id,
    },
    /// A probe behind a gate needs a build step its gate does not: the bundle
    /// of a gate is its own set-up plus its dependents, so they must share the
    /// gate's builds and world.
    ChildSetupDiffers {
        /// The probe.
        unit: Id,
        /// Its gate probe.
        gate: Id,
    },
}

impl fmt::Display for InputsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InputsError::Count {
                table,
                found,
                expected,
            } => write!(
                f,
                "`{table}` has {found} rows but the file declares {expected}; the executor refuses a file whose counts differ from its plan's, so rewrite the file from the plan it names"
            ),
            InputsError::ClassOutOfRange {
                unit,
                class,
                classes,
            } => write!(
                f,
                "probe {unit} kills class {class} but the file has {classes} classes (0..{classes}); the planner emitted a kill row against another class table, so rebuild `class_mass` and `kills` together"
            ),
            InputsError::ClassesNotAscending { unit } => write!(
                f,
                "the kill row of probe {unit} is not strictly ascending by class; the rule sums a row in class order and a class twice would count its mass twice, so sort the row and merge repeated classes"
            ),
            InputsError::BadKill { unit, class, q } => write!(
                f,
                "probe {unit} kills class {class} with probability {q}, outside (0, 1]; a probability of 0 is no kill and should be left out of the row"
            ),
            InputsError::BadMass { class, mass } => write!(
                f,
                "class {class} has mass {mass}; a mass is a chance and must be finite and not negative"
            ),
            InputsError::BadCost { unit, ms } => write!(
                f,
                "probe {unit} costs {ms} ms; a cost must be positive and finite, because density is gain over cost; give it a placeholder cost instead of 0"
            ),
            InputsError::BadSetup { step, ms } => write!(
                f,
                "step {step} costs {ms} ms to set up; a set-up cost must be finite and not negative"
            ),
            InputsError::StepOutOfRange {
                table,
                unit,
                step,
                steps,
            } => write!(
                f,
                "`{table}` of probe {unit} names step {step} but the file has {steps} steps; rebuild the per-step tables with the per-probe ones"
            ),
            InputsError::GateStepTaken {
                step,
                first,
                second,
            } => write!(
                f,
                "probes {first} and {second} are both the gate of step {step}; a step comes up when one probe passes, so give each gate its own step"
            ),
            InputsError::GatesJoin { unit } => write!(
                f,
                "probe {unit} waits for gate steps that do not form one chain (or a gate waits for itself); the rule orders a forest of gates, so make the model library refuse to emit a probe that needs two unrelated probes green first"
            ),
            InputsError::ChildSetupDiffers { unit, gate } => write!(
                f,
                "probe {unit} waits for gate probe {gate} but needs different builds or worlds than it does; list the gate's own builds and world in the dependent's `needs` and no others"
            ),
        }
    }
}

impl std::error::Error for InputsError {}

/// A step or a probe that is on no gate chain.
pub(crate) const NONE: u32 = u32::MAX;

/// What the gate structure of the inputs comes to, computed once.
pub(crate) struct Gates {
    /// The probe that is the gate of each step, or `NONE`.
    pub gate_unit_of_step: Vec<u32>,
    /// For each probe, the deepest gate probe it waits for, or `NONE`.
    pub parent: Vec<u32>,
}

impl DoubtInputs {
    /// Checks every table against the counts the file declares and the
    /// structural rules the rule relies on. [`crate::Rule::new`] panics with
    /// this error's message if it fails; an executor that would rather refuse
    /// the file calls this first.
    pub fn validate(&self) -> Result<(), InputsError> {
        self.analyse().map(|_| ())
    }

    /// The cost of one run of probe `u`, in milliseconds.
    #[inline]
    pub(crate) fn cost(&self, u: u32) -> f64 {
        self.cost_ms[u as usize].millis()
    }

    /// The gate step of probe `u`, if it is a gate.
    #[inline]
    pub(crate) fn gate_step(&self, u: u32) -> Option<StepIx> {
        self.gate_of.get(u as usize).copied().flatten()
    }

    pub(crate) fn analyse(&self) -> Result<Gates, InputsError> {
        let (n, s) = (self.units as usize, self.steps as usize);
        let count = |table: &'static str, found: usize, expected: usize| {
            if found == expected {
                Ok(())
            } else {
                Err(InputsError::Count {
                    table,
                    found,
                    expected,
                })
            }
        };
        count("kills", self.kills.rows(), n)?;
        count("cost_ms", self.cost_ms.len(), n)?;
        count("needs", self.needs.rows(), n)?;
        count("reach", self.reach.len(), n)?;
        count("setup_ms", self.setup_ms.len(), s)?;
        if !self.gate_of.is_empty() {
            count("gate_of", self.gate_of.len(), n)?;
        }
        for (class, &mass) in self.class_mass.iter().enumerate() {
            if !(mass.is_finite() && mass >= 0.0) {
                return Err(InputsError::BadMass {
                    class: class as u32,
                    mass,
                });
            }
        }
        for step in 0..s {
            let ms = self.setup_ms[step].millis();
            if !(ms.is_finite() && ms >= 0.0) {
                return Err(InputsError::BadSetup {
                    step: step as u32,
                    ms,
                });
            }
        }
        let classes = self.class_mass.len();
        for u in 0..n as u32 {
            let ms = self.cost(u);
            if !(ms.is_finite() && ms > 0.0) {
                return Err(InputsError::BadCost { unit: u, ms });
            }
            let mut prev: Option<u32> = None;
            for &(class, q) in self.kills.row(u as usize) {
                if class as usize >= classes {
                    return Err(InputsError::ClassOutOfRange {
                        unit: u,
                        class,
                        classes,
                    });
                }
                if prev.is_some_and(|p| p >= class) {
                    return Err(InputsError::ClassesNotAscending { unit: u });
                }
                prev = Some(class);
                if !(q > 0.0 && q <= 1.0) {
                    return Err(InputsError::BadKill { unit: u, class, q });
                }
            }
            for &step in self.needs.row(u as usize) {
                if step >= self.steps {
                    return Err(InputsError::StepOutOfRange {
                        table: "needs",
                        unit: u,
                        step,
                        steps: self.steps,
                    });
                }
            }
            if let Some(step) = self.gate_step(u)
                && step >= self.steps
            {
                return Err(InputsError::StepOutOfRange {
                    table: "gate_of",
                    unit: u,
                    step,
                    steps: self.steps,
                });
            }
        }

        let mut gate_unit_of_step = vec![NONE; s];
        for u in 0..n as u32 {
            if let Some(step) = self.gate_step(u) {
                let slot = &mut gate_unit_of_step[step as usize];
                if *slot != NONE {
                    return Err(InputsError::GateStepTaken {
                        step,
                        first: *slot,
                        second: u,
                    });
                }
                *slot = u;
            }
        }

        // The gates a probe waits for, as a sorted list: needs rows are not
        // promised sorted or free of repeats.
        let gates_of = |u: u32| -> Vec<u32> {
            let mut g: Vec<u32> = self
                .needs
                .row(u as usize)
                .iter()
                .copied()
                .filter(|&x| gate_unit_of_step[x as usize] != NONE)
                .collect();
            g.sort_unstable();
            g.dedup();
            g
        };
        let mut parent = vec![NONE; n];
        if gate_unit_of_step.iter().any(|&g| g != NONE) {
            let depth: Vec<u32> = (0..n as u32).map(|u| gates_of(u).len() as u32).collect();
            for u in 0..n as u32 {
                let mine = gates_of(u);
                let Some(&deepest) = mine
                    .iter()
                    .max_by_key(|&&x| (depth[gate_unit_of_step[x as usize] as usize], x))
                else {
                    continue;
                };
                let p = gate_unit_of_step[deepest as usize];
                // A chain: the gate it waits for deepest waits for all the others
                // and for nothing else. A cycle and a self-wait both fail here
                // because the depths cannot step up by exactly one.
                let theirs = gates_of(p);
                let chained = depth[p as usize] + 1 == depth[u as usize]
                    && theirs.iter().all(|x| mine.binary_search(x).is_ok())
                    && mine.binary_search(&deepest).is_ok();
                if !chained || p == u {
                    return Err(InputsError::GatesJoin { unit: u });
                }
                let builds = |v: u32| -> Vec<u32> {
                    let mut b: Vec<u32> = self
                        .needs
                        .row(v as usize)
                        .iter()
                        .copied()
                        .filter(|&x| gate_unit_of_step[x as usize] == NONE)
                        .collect();
                    b.sort_unstable();
                    b.dedup();
                    b
                };
                if builds(u) != builds(p) {
                    return Err(InputsError::ChildSetupDiffers { unit: u, gate: p });
                }
                parent[u as usize] = p;
            }
        }
        Ok(Gates {
            gate_unit_of_step,
            parent,
        })
    }
}
