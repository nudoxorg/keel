# Keel

Keel is an evidence-driven test framework for integration histories, dependency
models and incremental verification. Test definitions live in Nix; the runtime
and artifact-driven process adapters are Rust.

This repository contains the framework and the Nudox adapter. Product-owned
source fixtures and expected results stay in their product repositories.

```sh
nix build .#keel .#keel-nudox-harness
nix flake check
cargo test --locked -p backend-keel-harness --test driver
cargo test --locked -p keel-judge --test guidance
```

The Nudox adapter retains the `backend-keel-harness` executable name:

```sh
backend-keel-harness --manifest cases.json --inventory
backend-keel-harness --manifest cases.json --bin-dir /path/to/artifacts/bin --evidence /path/to/new-evidence
```

Evaluate the product's Nix case definitions into `cases.json`. The adapter
starts actual CLI, MCP, owner and native-worker processes and checks independently
authored expectations. It records exact manifest and artifact hashes, process
output, failed prerequisites and unexecuted work. It has no snapshot-blessing mode.

Nudox observations may order the complete inventory. They cannot drop cases,
validate cached results or grant a pass. Source-bound related edges support
measured call-graph statistics for the observed subgraph; global blast radius and
complexity remain unknown when relation coverage is not certified. See
[the observation contract](docs/nudox-guidance.md).

The project is under active development. A model declaration is not execution
evidence, successful pagination is not a coverage certificate, and retained hashes
do not attest historical execution. Unknown and blocked requirements remain
visible in reports.

The framework was extracted from the existing Keel workspace. Private operation
briefs, deployment data, machine configuration, live project captures and build
outputs are excluded. `IMPORTS.json` records the source revisions. The product
integration is developed alongside [NuDox Backend](https://github.com/nudoxorg/Backend).

## License

MIT OR Apache-2.0, at your option. See [LICENSE-MIT](LICENSE-MIT) and
[LICENSE-APACHE](LICENSE-APACHE).
