# agent-skills

Reusable skills my autonomous agents share across projects. Production-tested patterns from running long-lived agents 24/7 with real money on the line.

## Skills

### `brain/` — Long-term semantic memory
TF-IDF semantic search over a stored memory graph with entity linking, confidence scoring, and supersession (`evolve`) for updating outdated facts. The default cognition layer my agents reach for when they need to remember anything beyond the current session. Numpy + scikit-learn.

### `tradecraft/` — Trading experiment tracker
SQLite-backed, zero external deps. Stores autoresearch experiments with parent/lineage, trades, market regimes, and insights. Closes the loop between *"run 100 experiments"* and *"deploy the best config and monitor it"* — structured queries instead of TSV staring.

### `polymarket-trade/` — Polymarket execution layer
End-to-end trade execution on Polymarket: wallet setup, USDC.e funding (bridged USDC, not native — a footgun the docs don't surface), token approvals via Foundry `cast`, and order placement through `polymarket-cli`. Routes through an EU proxy because CLOB endpoints geoblock US datacenter IPs.

### `immunefi-hunter/` — Empirical attack simulator
Autonomous smart contract vulnerability hunter for Immunefi bounties. Forks mainnet via anvil, generates permutations of call sequences (2–5 deep), executes them with adversarial parameters, and scores by suspicion (unexpected state changes, broken invariants, profit opportunities). High-suspicion sequences seed deeper exploration. Combines computational attack-path search with LLM-driven reasoning — finds bugs that pattern matchers (Slither, Mythril) and human auditors miss.

### `memo/` — Household world model
Append-only state store for personal/household facts (devices, network, preferences). SQLite + FTS5, zero external deps. Linked entity graph for *"kitchen → has → Hue bulb"* style queries. Sister to `brain/` but scoped to ground-truth household state instead of agent cognition.

## Why these exist

Long-running agents need primitives that survive the ugly parts of production: context window collapse, model swaps, network failures, partial fills, ambiguous tool output. Each skill in this repo solves a specific pain point I hit running [br0br0](https://github.com/br0br0) and other agents continuously.

These pair with the three-layer durability hierarchy in [`agent-memory-skill`](https://github.com/sunnyvempati/agent-memory-skill).

## Stack

Python. SQLite for persistent state. Numpy + scikit-learn where ML is needed. Designed to drop into any agent harness — Claude Code skills, OpenClaw, custom orchestrators. No framework lock-in.

## Related

- [`agent-memory-skill`](https://github.com/sunnyvempati/agent-memory-skill) — three-layer memory architecture (filesystem → SQLite → conversation)
- [`weather-oracle`](https://github.com/sunnyvempati/weather-oracle) — production agent that uses several of these skills
- [`ncaa-bracket-2026`](https://github.com/sunnyvempati/ncaa-bracket-2026) — ensemble model + autoresearch loop
- [`eip7702-checker`](https://github.com/sunnyvempati/eip7702-checker) — sister tool to `immunefi-hunter`, focused on EIP-7702 delegate analysis

## License

MIT.
