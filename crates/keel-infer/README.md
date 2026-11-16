# keel-infer

The inference core of Keel. Pure algorithms over bitmaps: no IO, no clocks, no
randomness. Same inputs, same outputs, bit for bit, whatever the thread count.
Every tie goes to the smaller index.

## Explain: describe failures in the fewest words

Input: which tests ran, which failed, and the attributes tests carry (feature
tree nodes, languages, transports, packages). Output: a short list of causes.

* An attribute is **down** when every executed test that has it failed (or a
  `purity` fraction of them; the passers are listed as exceptions).
* A down attribute is **explained by** another when it stands on it in the
  feature tree, or when its failures are a strict subset of the other's.
  Attributes nothing explains are the roots; consequences are listed under them.
* Choose roots greedily by description length: naming an attribute costs
  log2(attrs) bits, every exception and every failure left unexplained costs
  log2(tests) bits. Stop when no root pays for itself. Failures nobody covers
  stay as the residue. `bits_listed` vs `bits_explained` says how much was saved.

"store.wal is down, and indexing and search are down because of it" is a cause
with two consequences instead of 1,600 red rows. If the best candidate would
only cover a handful of failures it can cost more to name than to list, and
then it is not named.

## Plan: run what removes the most doubt per second

Input: changed units with a prior chance each is wrong; for each test, which
units it can notice a fault in (probability `d`) and its cost.

* A test's value is `sum p_a * d` over the units it notices (the fault
  probability it could expose); its score is that per millisecond.
* `schedule()` is the greedy order assuming everything passes (lazy greedy over a
  window of the best candidates; scores only fall as other tests pass).
* `observe(test, passed)` updates beliefs. A pass is exact Bayes per unit. A
  failure uses the exact noisy-OR posterior, then treats units as independent
  again, which is an approximation: really the noticed units are
  negatively correlated ("one of them is wrong").
* `residual_risk(set)` is the chance at least one test in the set would fail:
  `1 - prod_units (1 - p * (1 - prod_tests (1 - d)))`.

## What the confidence number is not

The residual risk is a probability **under the model**. It assumes tests notice
faults independently of each other and that the notice probabilities and priors
are right. Neither is measured here: a suite of near-duplicate tests, or a
badly guessed `d`, makes the number too low. The simulation in `tests/sim.rs`
checks that the arithmetic is calibrated when the model is true, not that the
model is true.

## Layout

* `src/explain.rs`: `explain`, `Universe`, `Attr`; the cost model is in its header.
* `src/plan.rs`: `Planner`, `schedule`, the belief updates and their caveats.
* `tests/`: examples, properties (planted causes; lazy equals naive greedy),
  a seeded simulation, and ignored benchmarks (`--release -- --ignored`).
