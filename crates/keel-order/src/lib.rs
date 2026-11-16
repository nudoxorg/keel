//! keel-order: the rule that decides what a test runner starts next.
//!
//! A runner that has changed probes to run (tests, checks) and several workers
//! must pick, each time a worker is free, one of: bring up a build or a world
//! that some probes need, or start a probe. The cost of a set-up is paid once,
//! by the first probe of its group, so the right next probe is not always the
//! cheapest one or the most informative one: a probe that would detect a lot
//! but needs a build that takes minutes is worse to start than a slightly
//! weaker probe whose build is already done. This crate is that choice and
//! nothing else.
//!
//! # The rule, in plain words
//!
//! The planner has split the change's possible faults into *classes* and given
//! each class a mass: how likely the change carries it. A probe *kills* a class
//! with some probability when the class is present. The rule always takes the
//! action that detects the most still-undetected fault mass per second:
//!
//! * For a *group* of probes that need the same builds and world and are not
//!   up yet, the action is the group's set-up plus the best prefix of its
//!   probes, and what counts is the mass that bundle detects divided by the
//!   seconds it takes, set-up included. The group of greatest such density is
//!   set up first.
//! * Once a group is up, its probes compete one by one by mass detected per
//!   second of their own run.
//! * A probe counts as done the moment it is handed out, so that no other
//!   worker repeats what it will detect.
//! * A probe that detects nothing more still has to run (a `required` surface
//!   runs every changed probe): those come last, ones whose groups are up first,
//!   cheapest first.
//! * A *gate probe* is a check that other probes wait for (a fault experiment
//!   waits for its unfaulted cell to pass in the same world). Its value is
//!   priced together with the probes behind it, it comes up only when the
//!   executor reports that it passed, and if it fails the probes behind it
//!   are *stranded*: never handed out, listed by [`Rule::stranded`].
//!
//! Ties go to greater density, then to the probe that reaches fewer atoms, then
//! to the smaller number. The order is a function of the inputs and of the
//! sequence of `up` and `failed_setup` calls, and of nothing else: no clock, no
//! randomness, no hash iteration, no threads.
//!
//! # What the rule sees, and what it does not
//!
//! It sees numbers: probe numbers, step numbers, class masses, kill
//! probabilities, costs, reach sizes, and which probe is the gate of which step.
//! It never sees a node, a name or a result. It is told when a step is up or has
//! failed and for nothing else: while nothing fails it needs no results. A
//! confirmed failure ends the [`Rule`]; what to run after it (explanation order)
//! is a second, separate rule that belongs to the engine.
//!
//! The rule **orders; it never selects.** Which probes run is decided before
//! this crate is called, by what changed. Every probe given to the rule is
//! either handed out by [`Rule::next`] or reported by [`Rule::stranded`]; no
//! probability can remove one.
//!
//! # What is guaranteed
//!
//! The guarantee holds only when set-ups are private to a group, and then only
//! for the objective the rule optimises. Take one worker, and *private*
//! set-ups: every probe needs one group and groups share nothing. Let `J` be
//! the expected time until a present fault is first detected, summed over
//! faults. Then
//!
//! ```text
//! J(rule) <= (4 / α) · J(optimal),   α >= (1 - 1/e) · (B + L) / (B + L + c_max)
//! ```
//!
//! where `B` is the set-up of the densest bundle, `L` its run time and `c_max`
//! the longest probe. `α` is 0.63 when probes are short beside their set-up and
//! never below 0.316 while no probe costs more than `B + L`, so the bound is
//! between 6.4 and 12.7 times the optimum. The factor 4 is Golovin and Krause
//! (JAIR 2011), Theorem 15, read by the author of the design; its composition
//! with set-ups (treat a bundle as one item; the mediant inequality; the
//! Khuller–Moss–Naor budgeted-coverage step) is the design's own derivation and
//! has only the brute-force comparison below as a check. With `P` workers the
//! guarantee becomes additive, not multiplicative:
//! `J_P(rule) <= (4/α) · J_P(optimal) + F(T) · (B_max + c_max)`.
//!
//! The bound is a worst case, not a description. Measured against the exhaustive
//! optimum on 2,000 small instances (5 to 8 probes in 2 to 4 groups, set-ups
//! from negligible to dominant) the rule is on average 1.001 times the optimum
//! and at worst 1.12 times; ordering by gain per second of the probe alone, as
//! the planner this replaces did, is on average 2.0 to 2.4 times and at worst
//! 364 times. The crate's own tests reproduce these numbers.
//!
//! # What is not guaranteed
//!
//! * **Shared set-ups.** When a build or world is shared by several groups, or
//!   a gate chain has several worlds competing, no constant holds and a single
//!   group's bundle can be arbitrarily worse than the best set of groups on an
//!   adversarial instance. The tests measure the rule against the exhaustive
//!   optimum on random instances of that kind and report the worst ratio; that
//!   is evidence, not a bound.
//! * **Greedy, not optimal, inside a group.** A group's bundle is the best
//!   prefix of a density-greedy sequence, not the best subset. The best
//!   subset's density never rises while no step of its group comes up; the
//!   greedy prefix's density can (it is not monotone), but stays within
//!   `α' · best <= density <= best`, with the `α'` above. So a stale
//!   density is not an upper bound on a fresh one, and when the heap accepts a
//!   refreshed group over stale ones the bundle taken is within `α'` of the
//!   densest there is: the factor the guarantee already charges for using a
//!   prefix. The lazy procedure is the rule; the order with every density
//!   recomputed before every pick is only a reference it is compared with.
//! * **The offline order** is the rule on one worker, each `SetUp` followed at
//!   once by `up` and every gate passing; it is not a second procedure.
//! * **Gates in a cold world.** A gate takes the children that are best for the
//!   outermost cold bundle containing it, judged by the running gain and cost of
//!   everything already in that bundle, set-ups included (§4.8), at every depth.
//!   Without that the rule was up to 1.79 times the exhaustive optimum on random
//!   three-level instances; with it, 1.18. The recursive bundle is still a
//!   heuristic with no bound.
//! * **The additive objective.** The rule orders for expected faults detected,
//!   which agrees to first order with the chance that some fault is detected
//!   and is not the same number.
//! * **Costs are means.** Nothing is claimed about their variance.
//! * **Idle workers.** A worker is left idle ([`Pick::Idle`]) while the group
//!   the rule most wants is setting up and nothing else of value can start; on
//!   changes with few useful groups and many workers a list of probes can beat
//!   the online rule by about 10% (the design's D2b).
//! * **After a failure.** No guarantee at all; the rule's job ends there.
//!
//! # Using it
//!
//! ```
//! use keel_order::{Csr, Digest, DoubtInputs, Millis, Number, Pick, Rule};
//!
//! let ms = |v| Number::Placeholder { value: Millis(v) };
//! // Two probes in one binary (step 0); probe 1 detects the class probe 0 does, and another.
//! let inputs = DoubtInputs {
//!     plan: Digest::default(),
//!     units: 2,
//!     steps: 1,
//!     class_mass: vec![0.4, 0.1],
//!     kills: Csr::from_rows([vec![(0, 1.0)], vec![(0, 1.0), (1, 1.0)]]),
//!     cost_ms: vec![ms(10.0), ms(10.0)],
//!     needs: Csr::from_rows([vec![0], vec![0]]),
//!     setup_ms: vec![ms(2000.0)],
//!     reach: vec![3, 3],
//!     gate_of: vec![],
//! };
//! let mut rule = Rule::new(&inputs, &[]);
//! assert_eq!(rule.next(), Pick::SetUp(0)); // the binary first
//! assert_eq!(rule.next(), Pick::Idle);     // a second free worker has nothing to start yet
//! rule.up(0);
//! assert_eq!(rule.next(), Pick::Run(1));   // the probe that detects more
//! assert_eq!(rule.next(), Pick::Run(0));   // nothing left to detect: the rest still runs
//! assert_eq!(rule.next(), Pick::Finished);
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod inputs;
mod order;
mod rule;

pub use inputs::{Csr, Digest, DoubtInputs, Id, InputsError, Millis, Number, StepIx};
pub use order::{Order, OrderError, Selected};
pub use rule::{Pick, Rule, offline};

#[cfg(test)]
mod tests;
