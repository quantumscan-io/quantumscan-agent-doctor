# quantumscan-agent-doctor

Instant, zero-signup security check for an autonomous agent's wallet.

```bash
npx quantumscan-agent-doctor 0xYourAgentWallet
```

Checks, in one shot, with no API key required:

1. **Open ERC-20 approvals** — a single exploited approval can drain 100% of an approved
   token from an agent's wallet without any further action from the agent
2. **ECDSA nonce reuse** — if the agent's signing library ever reuses the same ephemeral
   nonce across two signatures, the private key is recoverable by pure algebra from public
   on-chain data. This is a mathematical certainty, not a heuristic — real losses have
   happened this way before (2013 Android SecureRandom Bitcoin thefts, the Sony PS3
   signing-key recovery).

Exit code is non-zero if a real risk is found (`1` for risky approvals, `2` for confirmed
nonce reuse) — safe to use as a CI gate before deploying an agent.

```bash
npx quantumscan-agent-doctor 0xYourAgentWallet --chain 137   # Polygon
npx quantumscan-agent-doctor 0xYourAgentWallet --chain 8453  # Base
```

## Higher rate limits

Free tier: a few checks/day per IP. For CI or heavier use:

```bash
export QUANTUMSCAN_API_KEY=qs_...  # free at quantumscan.io
```

## Full protection

This CLI is a point-in-time check. For continuous protection wired into an agent's
signing path, see [`@quantumscan/sdk`](https://www.npmjs.com/package/@quantumscan/sdk)
or [`langchain-quantumscan`](https://pypi.org/project/langchain-quantumscan/).

## License

MIT
