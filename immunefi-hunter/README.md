# immunefi-hunter

Autonomous smart contract vulnerability scanner for Immunefi bug bounties. Fetches active bounty programs, pulls contract source, runs static analysis + pattern matching, and generates Immunefi-format reports for findings.

Requires: `slither-analyzer`, `solc-select`, `foundry` (forge/anvil/cast), `requests`.

## Quick Start

```sh
# Scan a specific contract
python hunter.py scan 0x1234...abcd --chain ethereum

# Scan an Immunefi bounty program by slug  
python hunter.py bounty "uniswap" --depth full

# List active Immunefi programs sorted by max bounty
python hunter.py programs --sort bounty --min-bounty 50000

# Run full pipeline: fetch programs → filter → scan → report
python hunter.py sweep --min-bounty 10000 --max-age-days 30

# Check findings log
python hunter.py findings --severity critical,high

# Generate Immunefi report for a finding
python hunter.py report <finding-id> --format immunefi
```

## Commands

### `programs` — List Active Bounefi Programs
```sh
python hunter.py programs [--sort bounty|date|assets] [--min-bounty N] [--chain ethereum|bsc|polygon|arbitrum|all]
```
Fetches active programs from Immunefi API. Filters by bounty size, chain, and recency. Caches locally to avoid rate limits.

### `scan` — Analyze a Contract
```sh
python hunter.py scan <address> --chain <chain> [--depth quick|standard|full]
```
Depths:
- `quick` — Slither only, pattern matching against known vulns (~30s)
- `standard` — Slither + custom detectors + cross-function analysis (~2min)
- `full` — All above + forge fuzzing + anvil fork state checks (~10min)

### `bounty` — Scan an Immunefi Program
```sh
python hunter.py bounty <slug> [--depth standard] [--scope all|contracts|vaults]
```
Pulls all in-scope contracts for a bounty program and runs scans on each.

### `sweep` — Autonomous Hunting Pipeline
```sh
python hunter.py sweep [--min-bounty 10000] [--max-age-days 30] [--chains ethereum,arbitrum] [--hours 4]
```
The main autonomous loop:
1. Fetches active Immunefi programs matching filters
2. Prioritizes by: bounty_size × code_freshness × (1/audit_count)
3. Pulls contract source (Etherscan/Sourcify/GitHub)
4. Runs tiered analysis (quick → standard → full on flagged contracts)
5. Logs all findings to local DB
6. Generates reports for high-severity findings

### `findings` — View Scan Results
```sh
python hunter.py findings [--severity critical,high,medium] [--status new|reported|invalid]
```

### `report` — Generate Immunefi Report
```sh
python hunter.py report <finding-id> [--format immunefi|markdown]
```
Generates a properly formatted bug report with:
- Vulnerability description
- Impact assessment (funds at risk)
- Proof of concept (forge test)
- Recommended fix

## Vulnerability Patterns

Built-in detectors beyond Slither defaults:
- **Cross-function reentrancy** — state changes after external calls across multiple functions
- **Oracle manipulation** — spot price dependencies, TWAP window attacks
- **Flash loan vectors** — large balance assumptions, price impact paths
- **Precision loss** — division before multiplication, rounding in favor of attacker
- **Access control gaps** — missing modifiers, admin key risks, proxy upgrade auth
- **MEV/frontrun vectors** — slippage params, sandwich attack surfaces
- **Cross-chain bridge logic** — message replay, incomplete validation
- **Governance attacks** — flash loan voting, timelock bypasses
- **Token integration issues** — fee-on-transfer, rebasing, non-standard ERC20
- **Upgradability risks** — storage collisions, uninitialized proxies

## Architecture

```
hunter.py           — CLI entry point + orchestration
scanners/
  slither_scan.py   — Slither integration + custom detectors
  pattern_scan.py   — Regex + AST pattern matching
  fuzz_scan.py      — Forge-based property fuzzing
  state_scan.py     — Anvil fork live-state analysis
fetchers/
  immunefi.py       — Immunefi API client
  etherscan.py      — Contract source fetcher (multi-chain)
  sourcify.py       — Sourcify fallback
reporters/
  immunefi_fmt.py   — Immunefi report template
  markdown_fmt.py   — Generic markdown report
data/
  findings.db       — SQLite findings database
  programs.json     — Cached Immunefi programs
  scanned.json      — Scan history (avoid re-scanning)
```

## Cron Integration

```sh
# Daily sweep — 4 hours of autonomous scanning
python hunter.py sweep --min-bounty 10000 --hours 4

# Weekly fresh program check
python hunter.py programs --sort date --min-bounty 5000
```

## Notes

- Respects Etherscan rate limits (5 req/s free tier, uses API key if available)
- Findings DB prevents duplicate reports
- All PoCs use forge test framework — reproducible and verifiable
- Never submits reports automatically — human review required before submission
- Prioritizes programs with NO prior audits or recent code changes (highest alpha)
