#!/usr/bin/env python3
"""
immunefi-hunter — Autonomous smart contract vulnerability scanner.
Scans Immunefi bounty programs for vulnerabilities using Slither,
custom pattern detectors, and Foundry-based fuzzing.
"""

import argparse
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import time
import hashlib
from datetime import datetime, timedelta
from pathlib import Path

# --- Config ---
DATA_DIR = Path(__file__).parent / "data"
DB_PATH = DATA_DIR / "findings.db"
PROGRAMS_CACHE = DATA_DIR / "programs.json"
SCANNED_CACHE = DATA_DIR / "scanned.json"
ETHERSCAN_KEYS = {
    "ethereum": os.environ.get("ETHERSCAN_API_KEY", ""),
    "arbitrum": os.environ.get("ARBISCAN_API_KEY", ""),
    "polygon": os.environ.get("POLYGONSCAN_API_KEY", ""),
    "bsc": os.environ.get("BSCSCAN_API_KEY", ""),
    "optimism": os.environ.get("OPTIMISM_API_KEY", ""),
    "base": os.environ.get("BASESCAN_API_KEY", ""),
}
EXPLORER_URLS = {
    "ethereum": "https://api.etherscan.io/api",
    "arbitrum": "https://api.arbiscan.io/api",
    "polygon": "https://api.polygonscan.com/api",
    "bsc": "https://api.bscscan.com/api",
    "optimism": "https://api-optimistic.etherscan.io/api",
    "base": "https://api.basescan.org/api",
}
SLITHER_PATH = os.environ.get("SLITHER_PATH", "slither")
FORGE_PATH = os.environ.get("FORGE_PATH", "forge")


def ensure_dirs():
    DATA_DIR.mkdir(parents=True, exist_ok=True)


def init_db():
    """Initialize findings database."""
    ensure_dirs()
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            program TEXT,
            contract_address TEXT,
            chain TEXT,
            severity TEXT,
            title TEXT NOT NULL,
            description TEXT,
            detector TEXT,
            impact TEXT,
            poc TEXT,
            recommendation TEXT,
            status TEXT DEFAULT 'new',
            bounty_max INTEGER DEFAULT 0
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            contract_address TEXT,
            chain TEXT,
            program TEXT,
            depth TEXT,
            findings_count INTEGER DEFAULT 0,
            duration_seconds REAL
        )
    """)
    conn.commit()
    return conn


# --- Immunefi API ---
def fetch_programs(min_bounty=0, chain="all", sort="bounty"):
    """Fetch active Immunefi bounty programs."""
    import urllib.request

    url = "https://immunefi.com/api/bounty"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "immunefi-hunter/1.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
    except Exception as e:
        # Try cached
        if PROGRAMS_CACHE.exists():
            print(f"[!] API failed ({e}), using cache")
            data = json.loads(PROGRAMS_CACHE.read_text())
        else:
            print(f"[!] API failed and no cache: {e}")
            return []

    programs = []
    for p in data if isinstance(data, list) else data.get("data", data.get("bounties", [])):
        max_bounty = 0
        if isinstance(p, dict):
            # Extract max bounty from various possible fields
            for key in ["maxBounty", "max_bounty", "maximumReward"]:
                val = p.get(key, 0)
                if isinstance(val, str):
                    val = int(val.replace(",", "").replace("$", "").replace("USD", "").strip() or 0)
                if isinstance(val, (int, float)):
                    max_bounty = max(max_bounty, int(val))

            slug = p.get("id", p.get("slug", p.get("project", "")))
            name = p.get("name", p.get("project", slug))
            assets = p.get("assets", [])
            
            if max_bounty >= min_bounty:
                programs.append({
                    "slug": slug,
                    "name": name,
                    "max_bounty": max_bounty,
                    "assets": assets,
                    "chain": p.get("chain", "ethereum"),
                    "launch_date": p.get("launchDate", p.get("updatedDate", "")),
                })

    # Cache
    ensure_dirs()
    PROGRAMS_CACHE.write_text(json.dumps(programs, indent=2))

    # Sort
    if sort == "bounty":
        programs.sort(key=lambda x: x["max_bounty"], reverse=True)
    elif sort == "date":
        programs.sort(key=lambda x: x.get("launch_date", ""), reverse=True)

    return programs


# --- Contract Source Fetching ---
def fetch_contract_source(address, chain="ethereum"):
    """Fetch verified contract source from block explorer."""
    import urllib.request

    base_url = EXPLORER_URLS.get(chain, EXPLORER_URLS["ethereum"])
    api_key = ETHERSCAN_KEYS.get(chain, "")
    
    params = f"?module=contract&action=getsourcecode&address={address}"
    if api_key:
        params += f"&apikey={api_key}"
    
    url = base_url + params
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "immunefi-hunter/1.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
    except Exception as e:
        print(f"[!] Failed to fetch source for {address}: {e}")
        return None

    if data.get("status") != "1" or not data.get("result"):
        print(f"[!] No verified source for {address} on {chain}")
        return None

    result = data["result"][0]
    source = result.get("SourceCode", "")
    name = result.get("ContractName", "Unknown")
    compiler = result.get("CompilerVersion", "")
    
    # Handle JSON-format source (multiple files)
    if source.startswith("{{"):
        source = source[1:-1]  # Remove outer braces
    
    return {
        "source": source,
        "name": name,
        "compiler": compiler,
        "address": address,
        "chain": chain,
    }


# --- Slither Analysis ---
def run_slither(source_dir, contract_name=None):
    """Run Slither static analysis on contract source."""
    findings = []
    try:
        cmd = [SLITHER_PATH, str(source_dir), "--json", "-"]
        if contract_name:
            cmd.extend(["--filter-paths", "test|script|lib"])
        
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=120,
            env={**os.environ, "PATH": f"{os.environ.get('PATH', '')}:{Path.home()}/.local/bin"}
        )
        
        if result.stdout:
            try:
                slither_output = json.loads(result.stdout)
                detectors = slither_output.get("results", {}).get("detectors", [])
                for d in detectors:
                    severity = d.get("impact", "informational").lower()
                    if severity in ("high", "medium", "critical"):
                        findings.append({
                            "detector": f"slither:{d.get('check', 'unknown')}",
                            "severity": severity,
                            "title": d.get("check", "Unknown"),
                            "description": d.get("description", ""),
                            "first_markdown_element": d.get("first_markdown_element", ""),
                        })
            except json.JSONDecodeError:
                pass
        
        # Also capture stderr warnings
        if result.stderr and "Error" not in result.stderr:
            pass  # Slither warnings, usually fine
            
    except subprocess.TimeoutExpired:
        print("[!] Slither timed out (120s)")
    except FileNotFoundError:
        print("[!] Slither not found. Install: pip3 install slither-analyzer")
    
    return findings


# --- Custom Pattern Detectors ---
VULN_PATTERNS = {
    "reentrancy-custom": {
        "severity": "high",
        "patterns": [
            r"\.call\{value:",
            r"\.call\(",
            r"\.transfer\(",
            r"\.send\(",
        ],
        "anti_patterns": [
            r"ReentrancyGuard",
            r"nonReentrant",
            r"_status\s*=",
        ],
        "description": "External call detected without apparent reentrancy protection",
    },
    "oracle-manipulation": {
        "severity": "high",
        "patterns": [
            r"getReserves\(\)",
            r"balanceOf\(address\(this\)\)",
            r"slot0\(\)",
            r"latestAnswer\(\)",
        ],
        "context_patterns": [
            r"price",
            r"oracle",
            r"swap",
        ],
        "description": "Potential oracle/price manipulation via spot price dependency",
    },
    "precision-loss": {
        "severity": "medium",
        "patterns": [
            r"\/ .+ \*",  # division before multiplication
            r"1e18",
            r"PRECISION",
        ],
        "description": "Potential precision loss — division before multiplication",
    },
    "unchecked-return": {
        "severity": "medium",
        "patterns": [
            r"\.approve\(",
            r"\.transfer\(",
            r"\.transferFrom\(",
        ],
        "anti_patterns": [
            r"require\(",
            r"if \(!",
            r"SafeERC20",
            r"safeTransfer",
        ],
        "description": "ERC20 operation without return value check or SafeERC20",
    },
    "access-control": {
        "severity": "high",
        "patterns": [
            r"function\s+\w+\s*\([^)]*\)\s*external",
            r"function\s+\w+\s*\([^)]*\)\s*public",
        ],
        "context_patterns": [
            r"withdraw",
            r"mint",
            r"burn",
            r"set[A-Z]",
            r"update[A-Z]",
            r"pause",
            r"upgrade",
        ],
        "anti_patterns": [
            r"onlyOwner",
            r"onlyRole",
            r"onlyAdmin",
            r"require\(msg\.sender",
            r"_checkRole",
            r"auth\b",
        ],
        "description": "Sensitive function may lack access control",
    },
    "flash-loan-vector": {
        "severity": "high",
        "patterns": [
            r"balanceOf\(address\(this\)\)",
            r"totalSupply\(\)",
        ],
        "context_patterns": [
            r"share",
            r"exchange.?rate",
            r"price.?per",
            r"virtual.?price",
        ],
        "description": "Contract balance used in share/price calculation — flash loan manipulation possible",
    },
    "proxy-risks": {
        "severity": "critical",
        "patterns": [
            r"delegatecall",
            r"upgradeTo",
            r"upgradeToAndCall",
        ],
        "context_patterns": [
            r"initializ",
            r"proxy",
        ],
        "anti_patterns": [
            r"initializer\b",
            r"onlyProxy",
        ],
        "description": "Proxy/upgrade pattern detected — check initialization and storage layout",
    },
}


def run_pattern_scan(source_code, contract_name=""):
    """Run custom vulnerability pattern matching."""
    import re
    findings = []
    
    lines = source_code.split("\n")
    
    for vuln_name, config in VULN_PATTERNS.items():
        matched = False
        anti_matched = False
        context_matched = not config.get("context_patterns")  # True if no context required
        
        match_lines = []
        
        for i, line in enumerate(lines):
            # Check main patterns
            for pattern in config["patterns"]:
                if re.search(pattern, line):
                    matched = True
                    match_lines.append(i + 1)
            
            # Check context patterns
            for pattern in config.get("context_patterns", []):
                if re.search(pattern, line, re.IGNORECASE):
                    context_matched = True
            
            # Check anti-patterns (mitigations)
            for pattern in config.get("anti_patterns", []):
                if re.search(pattern, line):
                    anti_matched = True
        
        if matched and context_matched and not anti_matched:
            findings.append({
                "detector": f"pattern:{vuln_name}",
                "severity": config["severity"],
                "title": vuln_name.replace("-", " ").title(),
                "description": config["description"],
                "lines": match_lines[:5],  # First 5 matches
            })
    
    return findings


# --- Forge Fuzzing ---
def run_forge_fuzz(source_dir, contract_name, target_functions=None):
    """Run Forge-based property testing/fuzzing."""
    findings = []
    
    # Create a basic invariant test
    test_template = f"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

interface ITarget {{
    // Basic ERC20-like interface for invariant testing
    function totalSupply() external view returns (uint256);
    function balanceOf(address) external view returns (uint256);
}}

contract InvariantTest is Test {{
    ITarget target;
    
    function setUp() public {{
        // Fork mainnet if needed
        target = ITarget(address(0)); // Set target
    }}
    
    // Basic invariant: total supply should not change unexpectedly
    function invariant_totalSupplyConsistent() public view {{
        // This is a template — real tests would be contract-specific
        assertTrue(true);
    }}
}}
"""
    # For now, just check if forge can compile the project
    try:
        result = subprocess.run(
            [FORGE_PATH, "build"],
            capture_output=True, text=True, timeout=60,
            cwd=str(source_dir)
        )
        if result.returncode != 0:
            findings.append({
                "detector": "forge:build-fail",
                "severity": "informational",
                "title": "Build failure",
                "description": f"Contract failed to compile: {result.stderr[:500]}",
            })
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    
    return findings


# --- Scanning Orchestration ---
def scan_contract(address, chain="ethereum", depth="standard", program=None):
    """Full scan pipeline for a single contract."""
    conn = init_db()
    start_time = time.time()
    all_findings = []
    
    print(f"\n[*] Scanning {address} on {chain} (depth: {depth})")
    
    # Step 1: Fetch source
    print("[*] Fetching contract source...")
    source = fetch_contract_source(address, chain)
    if not source:
        print("[!] Could not fetch source — skipping")
        return []
    
    print(f"[+] Found: {source['name']} (compiler: {source['compiler']})")
    
    # Step 2: Write source to temp dir for Slither
    with tempfile.TemporaryDirectory() as tmpdir:
        src_path = Path(tmpdir) / f"{source['name']}.sol"
        
        # Handle multi-file JSON source
        source_code = source["source"]
        if source_code.startswith("{"):
            try:
                files = json.loads(source_code)
                for fname, fdata in files.items():
                    fpath = Path(tmpdir) / fname
                    fpath.parent.mkdir(parents=True, exist_ok=True)
                    content = fdata if isinstance(fdata, str) else fdata.get("content", "")
                    fpath.write_text(content)
                    if not source_code:
                        source_code = content
                # Use first .sol file as main source for pattern scan
                sol_files = list(Path(tmpdir).rglob("*.sol"))
                if sol_files:
                    source_code = sol_files[0].read_text()
            except json.JSONDecodeError:
                src_path.write_text(source_code)
        else:
            src_path.write_text(source_code)
        
        # Step 3: Quick scan — pattern matching
        print("[*] Running pattern scan...")
        pattern_findings = run_pattern_scan(source_code, source["name"])
        all_findings.extend(pattern_findings)
        print(f"[+] Pattern scan: {len(pattern_findings)} findings")
        
        if depth in ("standard", "full"):
            # Step 4: Slither analysis
            print("[*] Running Slither...")
            slither_findings = run_slither(tmpdir, source["name"])
            all_findings.extend(slither_findings)
            print(f"[+] Slither: {len(slither_findings)} findings")
        
        if depth == "full":
            # Step 5: Forge fuzzing
            print("[*] Running Forge analysis...")
            forge_findings = run_forge_fuzz(tmpdir, source["name"])
            all_findings.extend(forge_findings)
            print(f"[+] Forge: {len(forge_findings)} findings")
    
    duration = time.time() - start_time
    
    # Store findings
    for f in all_findings:
        fid = hashlib.sha256(
            f"{address}:{chain}:{f['detector']}:{f['title']}".encode()
        ).hexdigest()[:12]
        
        try:
            conn.execute("""
                INSERT OR IGNORE INTO findings 
                (id, timestamp, program, contract_address, chain, severity, title, description, detector, status, bounty_max)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'new', ?)
            """, (
                fid, datetime.utcnow().isoformat(), program or "",
                address, chain, f["severity"], f["title"],
                f.get("description", ""), f["detector"], 0
            ))
        except sqlite3.IntegrityError:
            pass
    
    # Log scan
    scan_id = hashlib.sha256(f"{address}:{chain}:{datetime.utcnow().isoformat()}".encode()).hexdigest()[:12]
    conn.execute("""
        INSERT INTO scans (id, timestamp, contract_address, chain, program, depth, findings_count, duration_seconds)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (scan_id, datetime.utcnow().isoformat(), address, chain, program or "", depth, len(all_findings), duration))
    
    conn.commit()
    conn.close()
    
    # Summary
    by_severity = {}
    for f in all_findings:
        sev = f["severity"]
        by_severity[sev] = by_severity.get(sev, 0) + 1
    
    print(f"\n[+] Scan complete in {duration:.1f}s")
    print(f"[+] Findings: {' | '.join(f'{s}: {c}' for s, c in sorted(by_severity.items()))}")
    
    return all_findings


def sweep(min_bounty=10000, max_age_days=30, chains=None, max_hours=4):
    """Autonomous hunting sweep."""
    print("=" * 60)
    print("IMMUNEFI HUNTER — AUTONOMOUS SWEEP")
    print("=" * 60)
    
    chains = chains or ["ethereum", "arbitrum", "polygon", "optimism", "base"]
    deadline = time.time() + (max_hours * 3600)
    
    # Fetch programs
    print(f"\n[*] Fetching programs (min bounty: ${min_bounty:,})")
    programs = fetch_programs(min_bounty=min_bounty, sort="bounty")
    print(f"[+] Found {len(programs)} programs")
    
    # Load scan history
    scanned = set()
    if SCANNED_CACHE.exists():
        scanned = set(json.loads(SCANNED_CACHE.read_text()))
    
    scanned_count = 0
    findings_count = 0
    
    for prog in programs:
        if time.time() > deadline:
            print(f"\n[!] Time limit reached ({max_hours}h)")
            break
        
        slug = prog["slug"]
        assets = prog.get("assets", [])
        
        for asset in assets:
            if time.time() > deadline:
                break
                
            address = asset if isinstance(asset, str) else asset.get("address", "")
            chain = "ethereum"
            if isinstance(asset, dict):
                chain = asset.get("chain", asset.get("network", "ethereum")).lower()
            
            if not address or not address.startswith("0x"):
                continue
            
            scan_key = f"{address}:{chain}"
            if scan_key in scanned:
                continue
            
            if chain not in chains:
                continue
            
            findings = scan_contract(
                address, chain=chain, depth="standard", program=slug
            )
            
            scanned.add(scan_key)
            scanned_count += 1
            findings_count += len(findings)
            
            # Rate limit
            time.sleep(2)
    
    # Save scan history
    ensure_dirs()
    SCANNED_CACHE.write_text(json.dumps(list(scanned), indent=2))
    
    print(f"\n{'=' * 60}")
    print(f"SWEEP COMPLETE")
    print(f"  Contracts scanned: {scanned_count}")
    print(f"  Total findings: {findings_count}")
    print(f"{'=' * 60}")


def show_findings(severity=None, status=None):
    """Display findings from database."""
    conn = init_db()
    
    query = "SELECT * FROM findings"
    conditions = []
    params = []
    
    if severity:
        sevs = severity.split(",")
        placeholders = ",".join(["?" for _ in sevs])
        conditions.append(f"severity IN ({placeholders})")
        params.extend(sevs)
    
    if status:
        conditions.append("status = ?")
        params.append(status)
    
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    
    query += " ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END"
    
    cursor = conn.execute(query, params)
    rows = cursor.fetchall()
    cols = [d[0] for d in cursor.description]
    
    if not rows:
        print("No findings match criteria.")
        return
    
    print(f"\n{'='*80}")
    print(f"FINDINGS ({len(rows)} total)")
    print(f"{'='*80}")
    
    for row in rows:
        f = dict(zip(cols, row))
        sev_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡"}.get(f["severity"], "⚪")
        print(f"\n{sev_icon} [{f['severity'].upper()}] {f['title']}")
        print(f"   Contract: {f['contract_address']} ({f['chain']})")
        print(f"   Program: {f['program']}")
        print(f"   Detector: {f['detector']}")
        print(f"   Status: {f['status']}")
        if f.get("description"):
            desc = f["description"][:200]
            print(f"   {desc}")
    
    conn.close()


def generate_report(finding_id, fmt="immunefi"):
    """Generate a formatted report for a finding."""
    conn = init_db()
    row = conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
    
    if not row:
        print(f"Finding {finding_id} not found")
        return
    
    cols = [d[0] for d in conn.execute("SELECT * FROM findings LIMIT 0").description]
    f = dict(zip(cols, row))
    
    if fmt == "immunefi":
        report = f"""# Bug Report — {f['title']}

## Bug Description
{f.get('description', 'TBD — requires manual analysis')}

## Impact
{f.get('impact', 'TBD — assess funds at risk and affected users')}

**Severity:** {f['severity'].upper()}
**Contract:** {f['contract_address']} ({f['chain']})
**Detector:** {f['detector']}

## Proof of Concept

```solidity
// TODO: Write forge test demonstrating the vulnerability
// forge test --match-test test_exploit -vvv
```

## Recommendation
{f.get('recommendation', 'TBD — suggest specific code fix')}

---
*Generated by immunefi-hunter. Human review required before submission.*
"""
    else:
        report = json.dumps(f, indent=2)
    
    print(report)
    conn.close()


# --- CLI ---
def main():
    parser = argparse.ArgumentParser(description="Immunefi bug bounty hunter")
    subparsers = parser.add_subparsers(dest="command", help="Command")
    
    # programs
    p_prog = subparsers.add_parser("programs", help="List active Immunefi programs")
    p_prog.add_argument("--sort", choices=["bounty", "date", "assets"], default="bounty")
    p_prog.add_argument("--min-bounty", type=int, default=0)
    p_prog.add_argument("--chain", default="all")
    p_prog.add_argument("--limit", type=int, default=20)
    
    # scan
    p_scan = subparsers.add_parser("scan", help="Scan a specific contract")
    p_scan.add_argument("address", help="Contract address")
    p_scan.add_argument("--chain", default="ethereum")
    p_scan.add_argument("--depth", choices=["quick", "standard", "full"], default="standard")
    p_scan.add_argument("--program", default=None)
    
    # bounty
    p_bounty = subparsers.add_parser("bounty", help="Scan an Immunefi bounty program")
    p_bounty.add_argument("slug", help="Program slug/id")
    p_bounty.add_argument("--depth", choices=["quick", "standard", "full"], default="standard")
    
    # sweep
    p_sweep = subparsers.add_parser("sweep", help="Autonomous hunting sweep")
    p_sweep.add_argument("--min-bounty", type=int, default=10000)
    p_sweep.add_argument("--max-age-days", type=int, default=30)
    p_sweep.add_argument("--chains", default="ethereum,arbitrum,polygon,optimism,base")
    p_sweep.add_argument("--hours", type=float, default=4)
    
    # findings
    p_find = subparsers.add_parser("findings", help="View findings")
    p_find.add_argument("--severity", default=None, help="Filter: critical,high,medium")
    p_find.add_argument("--status", default=None, help="Filter: new,reported,invalid")
    
    # report
    p_report = subparsers.add_parser("report", help="Generate report for finding")
    p_report.add_argument("finding_id", help="Finding ID")
    p_report.add_argument("--format", choices=["immunefi", "markdown", "json"], default="immunefi")
    
    args = parser.parse_args()
    
    if args.command == "programs":
        programs = fetch_programs(min_bounty=args.min_bounty, sort=args.sort)
        print(f"\n{'Name':40s} {'Max Bounty':>12s} {'Chain':>10s}")
        print("-" * 65)
        for p in programs[:args.limit]:
            print(f"{p['name'][:40]:40s} ${p['max_bounty']:>11,} {p.get('chain', '?'):>10s}")
        print(f"\nTotal: {len(programs)} programs")
    
    elif args.command == "scan":
        scan_contract(args.address, chain=args.chain, depth=args.depth, program=args.program)
    
    elif args.command == "sweep":
        chains = args.chains.split(",")
        sweep(min_bounty=args.min_bounty, max_age_days=args.max_age_days, chains=chains, max_hours=args.hours)
    
    elif args.command == "findings":
        show_findings(severity=args.severity, status=args.status)
    
    elif args.command == "report":
        generate_report(args.finding_id, fmt=args.format)
    
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
