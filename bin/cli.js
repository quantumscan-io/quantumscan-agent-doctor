#!/usr/bin/env node
/**
 * quantumscan-agent-doctor — instant security check for an agent wallet.
 *
 * Usage:
 *   npx quantumscan-agent-doctor 0xYourAgentWallet
 *   npx quantumscan-agent-doctor 0xYourAgentWallet --chain 137
 *
 * Zero config, zero signup. Calls two public QuantumScan checks against the
 * wallet address and prints a terminal report:
 *   1. Open ERC-20 approvals (a single exploited approval can drain the wallet)
 *   2. ECDSA nonce reuse (mathematically certain key compromise, not a heuristic)
 *
 * Free tier: a few checks per day per IP, no API key required. For CI or
 * heavier use, set QUANTUMSCAN_API_KEY (get one free at quantumscan.io).
 */

const BASE_URL = process.env.QUANTUMSCAN_API_URL || "https://quantumscan.io";
const API_KEY = process.env.QUANTUMSCAN_API_KEY || "";

const RESET = "\x1b[0m";
const BOLD = "\x1b[1m";
const DIM = "\x1b[2m";
const RED = "\x1b[31m";
const YELLOW = "\x1b[33m";
const GREEN = "\x1b[32m";
const CYAN = "\x1b[36m";

function color(text, code) {
  if (process.env.NO_COLOR) return text;
  return `${code}${text}${RESET}`;
}

function parseArgs(argv) {
  const args = argv.slice(2);
  let wallet = null;
  let chain = 1;
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--chain" || args[i] === "-c") {
      chain = parseInt(args[++i], 10) || 1;
    } else if (args[i] === "--version" || args[i] === "-v") {
      console.log(require("../package.json").version);
      process.exit(0);
    } else if (args[i] === "--help" || args[i] === "-h") {
      printHelp();
      process.exit(0);
    } else if (!wallet && /^0x[0-9a-fA-F]{40}$/.test(args[i])) {
      wallet = args[i];
    }
  }
  return { wallet, chain };
}

function printHelp() {
  console.log(`
${BOLD}quantumscan-agent-doctor${RESET} — instant security check for an agent wallet

Usage:
  npx quantumscan-agent-doctor <0xWalletAddress> [--chain <id>]

Options:
  -c, --chain <id>   Chain ID (default: 1 = Ethereum. 137=Polygon, 42161=Arbitrum, 8453=Base)
  -v, --version      Print version
  -h, --help         Show this help

Env vars:
  QUANTUMSCAN_API_KEY   Optional. Free key at https://quantumscan.io for higher limits.
`);
}

async function fetchJson(path) {
  const headers = { "User-Agent": "quantumscan-agent-doctor" };
  if (API_KEY) headers["X-API-Key"] = API_KEY;
  const res = await fetch(`${BASE_URL}${path}`, { headers });
  const body = await res.json().catch(() => ({}));
  return { ok: res.ok, status: res.status, body };
}

function riskColor(level) {
  if (level === "critical" || level === "compromised") return RED;
  if (level === "high" || level === "medium") return YELLOW;
  return GREEN;
}

async function main() {
  const { wallet, chain } = parseArgs(process.argv);

  if (!wallet) {
    printHelp();
    process.exit(1);
  }

  console.log(`\n${BOLD}QuantumScan Agent Doctor${RESET} ${DIM}— checking ${wallet} on chain ${chain}...${RESET}\n`);

  const [guard, nonce] = await Promise.all([
    fetchJson(`/api/agent/guard?wallet=${wallet}&network=${chain}`),
    fetchJson(`/api/agent/nonce-reuse-check?wallet=${wallet}&network=${chain}`),
  ]);

  let exitCode = 0;

  // ── Approvals ──────────────────────────────────────────────────────────
  console.log(color("1. Open ERC-20 approvals", BOLD));
  if (guard.status === 402) {
    console.log(
      `   ${color("⚠ rate-limited", YELLOW)} — free tier exhausted for today. Set QUANTUMSCAN_API_KEY for a free key (quantumscan.io) or try again tomorrow.`
    );
  } else if (!guard.ok) {
    console.log(`   ${color("✗ check failed", DIM)} (HTTP ${guard.status})`);
  } else {
    const { overallRisk, summary, immediateActions } = guard.body;
    const rc = riskColor(overallRisk);
    console.log(`   Overall risk: ${color(overallRisk.toUpperCase(), rc)}`);
    console.log(
      `   ${summary.critical} critical, ${summary.high} high, ${summary.medium} medium, ${summary.totalRisky} risky total`
    );
    if (overallRisk === "critical" || overallRisk === "high") exitCode = 1;
    for (const action of (immediateActions || []).slice(0, 3)) {
      console.log(`   ${color("→", CYAN)} ${action}`);
    }
  }

  console.log();

  // ── Nonce reuse ────────────────────────────────────────────────────────
  console.log(color("2. ECDSA nonce reuse (mathematical certainty, not a heuristic)", BOLD));
  if (nonce.status === 402) {
    console.log(`   ${color("⚠ rate-limited", YELLOW)} — see above.`);
  } else if (!nonce.ok) {
    console.log(`   ${color("✗ check failed", DIM)} (HTTP ${nonce.status})`);
  } else {
    const { verdict, transactionsChecked, recommendation } = nonce.body;
    const rc = riskColor(verdict);
    console.log(`   Verdict: ${color(verdict.toUpperCase(), rc)} ${DIM}(${transactionsChecked} tx checked)${RESET}`);
    if (verdict === "compromised") {
      exitCode = 2;
      console.log(`   ${color("→", RED)} ${recommendation}`);
    }
  }

  console.log(`\n${DIM}Full report + more checks: ${BASE_URL}/en/dashboard${RESET}`);
  console.log(`${DIM}Useful? Star the scanner: https://github.com/quantumscan-io/scanner-core${RESET}\n`);

  process.exit(exitCode);
}

main().catch((err) => {
  console.error(color(`Error: ${err.message}`, RED));
  process.exit(3);
});
