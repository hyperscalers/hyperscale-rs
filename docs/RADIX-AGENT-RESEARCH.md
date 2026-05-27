# Radix Agent Economy — Consolidated Research

> Compiled: 2026-05-27 | Session: 2026-05-25 deep-dive
> Author: bigdevxrd | Sources: Discord (xStelea, flightofthefox), GitHub, Radix docs

---

## 1. Agent SDK Landscape (May 2026)

### Major Frameworks

| Framework | Focus | Radix Support |
|-----------|-------|---------------|
| **Claude Agent SDK** | Anthropic's native agent framework | None |
| **OpenAI Agents** | OpenAI function-calling agents | None |
| **LangChain / LangGraph** | Orchestration, graph-based workflows | None |
| **CrewAI** | Multi-agent role-based collaboration | None |
| **AutoGen** (Microsoft) | Multi-agent conversation patterns | None |
| **Vercel AI SDK** | Next.js-native streaming, tool use | None — but best fit for guild-saas |

### Crypto-Specific Frameworks

| Framework | Chains | Radix Support |
|-----------|--------|---------------|
| **GOAT SDK** | 200+ chains (EVM, Solana, Sui, Aptos…) | **None** |
| **ElizaOS** | Multi-chain agent OS | None (xStelea forked it) |
| **Virtuals Protocol** | Agent token launchpad | None |

### Recommendation

- **guild-saas**: Use **Vercel AI SDK** — Next.js native, streaming, tool calling built-in
- Build custom **Radix tools** wrapping RDT + Gateway SDK + Radix Engine Toolkit
- **Radix has ZERO agent SDK coverage** — massive first-mover opportunity
- xStelea's `radix-agent-toolkit` (in radix-web3.js) is the closest thing that exists

---

## 2. Radix Tooling Available

### Official SDKs

| Package | Purpose | Status |
|---------|---------|--------|
| `@radixdlt/radix-dapp-toolkit` (RDT) | Wallet connection, √ Connect Button | Stable, maintained |
| `@radixdlt/babylon-gateway-api-sdk` | Gateway API queries (balances, txs, resources) | Stable |
| **Radix Engine Toolkit** (WASM) | Programmatic manifest building, signing, SBOR | Stable, critical for agents |
| **ROLA** (Radix Off-Ledger Auth) | Wallet-signed challenges for server auth | Stable |

### New / Community

| Package | Purpose | Status |
|---------|---------|--------|
| `rdx-cli@0.2.0` (xStelea) | CLI for manifests, x402 payments, Subintents, LLM context | Active dev |
| `@steleaio/radix-engine-toolkit` v2.0.0 | Enhanced TS wrapper with V2 tx builders | Published |
| `gateway-ez-mode` (xStelea) | Simplified Gateway helpers + SBOR parsing | Stable |
| `sbor-ez-mode` (xStelea) | Parse Scrypto SBOR JSON → JS objects | Stable |
| `radix-agent-toolkit` (xStelea) | GOAT SDK wallet integration for Radix | Early |

### Key Capability: `rdx llm`

The `rdx-cli` includes an `rdx llm` command that outputs Radix context for LLMs — essentially making any AI agent Radix-aware by piping domain knowledge. This is a critical building block.

---

## 3. xStelea's Contributions

### Core Original Projects

| Repo | Language | Description |
|------|----------|-------------|
| **radix-web3.js** ⭐7 | TypeScript | Monorepo: rdx-cli, gateway wrapper, tx-tool, radix-connect, radix-agent-toolkit, sbor-ez-mode, x402 example. Effect-TS based. RAP/1 protocol spec |
| **radix-vaults** | TypeScript | Full-stack multisig vault management (React 19 + Effect + PostgreSQL). Team badges, proposals, ROLA auth |
| **multisig** | Rust | Axum-based multisig tx orchestrator. Subintent pre-auth, fee abstraction, validity monitoring |
| **gateway-ez-mode** | TypeScript | Higher-level Gateway API wrapper (state, stream, tx polling, ROLA, domains) |
| **radix-context** ⭐3 | Shell | AI agent knowledge base: 20+ context docs (Effect-TS, Scrypto, TanStack). `agents.md` standard |
| **awesome-radix-mcp-servers** ⭐2 | JavaScript | MCP servers: attos-world (DeFi yields), sbor-ez-mode (schema gen), Astrolescent |
| **scripts** ⭐1 | Shell | Git/tmux/k8s workflow scripts with fzf |
| **helpers** | Shell | Zsh keybindings for scripts |
| **radix-mofos** | — | NFT collection project (mostly empty) |
| **consultation_v2** | TypeScript | Governance dApp (reference for radix-vaults patterns) |

### Key Forks (showing what he's investigating)

| Repo | Original | Why |
|------|----------|-----|
| **x402** | Coinbase x402 | Radix exact scheme spec (sponsored + non-sponsored payment modes) |
| **typescript-radix-engine-toolkit** | Official RET | Published as `@steleaio/radix-engine-toolkit` v2.0.0 with V2 tx builders |
| **radix-dapp-toolkit** | Official RDT | Contributing upstream improvements |
| **sargon** | RDX Works | Radix wallet library (Rust) |
| **eliza** / **eliza-starter** | ElizaOS | AI agent framework exploration |
| **goat** | GOAT SDK | Onchain agent framework — added Radix wallet integration |
| **a2a-agent-coder** | OpenRouter | Agent-to-agent coding |
| **sandcastle** | sandcastle | Sandboxed coding agent orchestration |

### What xStelea Has Solved

- ✅ Manifest building programmatically (rdx-cli, RET wrapper)
- ✅ x402 payment protocol spec for Radix (sponsored + non-sponsored)
- ✅ Subintent-based pre-authorization flows (multisig repo)
- ✅ SBOR parsing for JS/TS (sbor-ez-mode)
- ✅ AI context injection (radix-context, rdx llm)
- ✅ MCP server ecosystem bootstrap (awesome-radix-mcp-servers)
- ✅ GOAT SDK Radix wallet adapter (radix-agent-toolkit)
- ✅ ROLA authentication patterns (gateway-ez-mode, radix-vaults)

### What's Still Needed

- ❌ Full agent SDK (not just wallet adapter — needs task execution, memory, planning)
- ❌ Agent-to-agent communication protocol on Radix
- ❌ On-chain reputation system
- ❌ Agent registry component
- ❌ Fee abstraction for autonomous agents (AgentAccount pattern)
- ❌ Production multisig (current is Stokenet only)

---

## 4. Xi'an Architecture Principles

> Sources: xStelea + flightofthefox (Radix core team), Discord discussions

### UNBUNDLE EVERYTHING

The single most important design principle for Xi'an:

- **Smallest atomic unit per transaction** — never batch independent operations
- **2 txs × 2 shards > 1 tx × 3 shards** — shard count is the dominant cost factor
- **Provisioning cost**: bundling forces shards to know each other's balances unnecessarily, creating cross-shard overhead that doesn't exist with unbundled txs
- **Partial execution sharding**: Xi'an's cross-shard atomic commitment is its differentiator — design around it, don't fight it

### Fee Model

- **Fees follow emissions, not demand** — fees should drop to capture market share, not spike with congestion
- **Abundant blockspace** — Xi'an is designed for throughput, not artificial scarcity
- Priority is shard locality, not fee bidding (opposite of EVM gas auctions)

### NOT EVM — Core Mental Model Shifts

| EVM Concept | Radix Equivalent | Key Difference |
|-------------|-------------------|----------------|
| Tokens (ERC-20) | **Badges** | Native resources, not contract state |
| Smart contracts | **Components** | Instantiated blueprints with state |
| Calldata | **Manifests** | Declarative transaction intents |
| Account-oriented | **Resource-oriented** | Assets are first-class, not ledger entries |
| msg.sender | **Proof/Badge auth** | Capability-based, not identity-based |
| approve+transferFrom | **Bucket passing** | Direct resource movement, no approvals |

---

## 5. AgentAccount Concept

> Source: flightofthefox (Radix core team)

A purpose-built account component for autonomous agents:

### Design

- **Badge-owned**: An agent's account is controlled by a badge NFT, not a private key
- **Restricted sends**: Can only send to other AgentAccount instances (sandboxed agent economy)
- **Fast path execution**: Eligible for Xi'an's fast consensus path (single-shard, no cross-shard coordination)
- **Normal account top-up**: Users fund agent accounts via standard transactions
- **Single-shard affinity**: Designed to live on one shard for minimal footprint

### Why This Matters

- Agents don't need full account capabilities (no staking, no complex DeFi)
- Restricted sends prevent agents from draining funds to arbitrary addresses
- Fast path means agent-to-agent payments settle in ~200ms
- Badge ownership means the controlling entity can be a component, DAO, or user

### Implementation Path

1. Scrypto blueprint: `AgentAccount` component with badge auth
2. Methods: `deposit()`, `withdraw_to_agent(other: AgentAccount)`, `get_balance()`
3. Auth: badge-gated, with optional time-lock or spending limits
4. Registry integration: AgentAccount address → agent metadata

---

## 6. DeFi Mechanics

### Deviation vs. Slippage — Critical Distinction

| Term | Definition | Source |
|------|-----------|--------|
| **Deviation** | Difference between two pre-trade price sources (e.g., TradingView signal vs. oracle price) | Signal quality metric |
| **Slippage** | Difference between expected execution price and actual fill price | Execution quality metric |

### Oracle vs. TradingView

- **Oracle price** = execution truth (what the DEX pool actually offers)
- **TradingView price** = signal trigger (what your alert fired on)
- These can diverge significantly, especially for illiquid pairs or during volatility

### Auto-Trader Fix

The auto-trader was rejecting trades when TradingView price deviated from oracle price. This is wrong:

- **Correct behavior**: Execute at oracle price, don't reject on deviation
- The TradingView alert is just a trigger — the oracle price is what matters for execution
- **Slippage tolerance**: Set 2% on oracle price for manifest construction
- Deviation is informational only — log it, don't gate on it

### Manifest Construction

```
# Pseudo-manifest for agent trade
CALL_METHOD pool_address "swap"
    Bucket("xrd_bucket")
    Decimal("min_output")  # oracle_price * (1 - 0.02 slippage)
;
```

---

## 7. Agent Economy Design (Radix-Native)

> NOT EVM patterns. No gas auctions, no MEV, no token-gated access.

### Agent Registry

- **Badge NFT per agent**: Non-fungible resource with agent metadata (name, capabilities, version)
- **Deposit for sybil resistance**: Small XRD deposit to create agent identity (not priority-based)
- **On-chain metadata**: Agent type, supported tasks, endpoint/connection info
- **NOT a priority system**: All agents are equal; quality differentiation via reputation

### Reputation System

- **Off-chain computation**: Reputation scores calculated off-chain (too expensive on-chain)
- **Periodic on-chain commitment**: Hash of reputation state committed to ledger at intervals
- **Decay over time**: Inactive agents lose reputation — prevents stale high-reputation squatting
- **Domain-specific**: Trading agents rated on PnL, task agents on completion rate, etc.

### Priority Model

- **Shard locality over fee bidding**: Design agents to minimize cross-shard transactions
- **Abundant blockspace**: Xi'an doesn't need priority auctions — there's room for everyone
- **Single-shard affinity**: Keep agent state and frequent interactions on the same shard

### Payment Flows

- **Unbundled per-recipient txs**: One payment = one transaction (Xi'an principle)
- **x402 Subintents**: HTTP-native payment protocol for agent-to-agent payments
- **Pre-authorized spending**: Subintent-based budgets agents can draw from
- **No approve pattern**: Direct bucket transfers, not ERC-20 style approvals

### Three Economic Roles

| Role | Function | Example |
|------|----------|---------|
| **Risk Taker** | Puts capital at risk for returns | Trading agent, liquidity provider |
| **Fee Payer** | Pays transaction fees on behalf of others | Sponsor, platform operator |
| **Facilitator** | Coordinates between parties, earns facilitation fee | Marketplace, escrow, router |

---

## 8. Mapping to Projects

### guild-saas

- **Role**: Marketplace platform (Facilitator)
- **Agent use**: Worker agents (task execution), Poster agents (task creation/management)
- **On-chain**: Escrow blueprint (built), task NFTs, completion proofs
- **Reputation**: Task completion rate, response time, quality scores
- **Payment**: x402 Subintents for milestone-based escrow release
- **Stack**: Next.js + Vercel AI SDK + custom Radix tools

### auto-trader-xrd

- **Role**: Trading infrastructure (Risk Taker)
- **Agent use**: Signal agents (TradingView → intent), Execution agents (manifest building + submission)
- **On-chain**: Trade execution, PnL tracking
- **Reputation**: Signal accuracy, risk-adjusted returns, win rate
- **Fix needed**: Deviation mode → execute at oracle price with 2% slippage tolerance
- **Stack**: Node.js bot + Radix manifests

### defi-farmer

- **Role**: Yield optimization (Risk Taker)
- **Agent use**: Strategy agents (yield scanning), Rebalance agents (position management)
- **On-chain**: LP positions, vault deposits, harvest txs
- **Reputation**: Returns vs. benchmark, drawdown history, gas efficiency
- **Stack**: TBD — likely similar to auto-trader

### hyperscale-rs

- **Role**: Node infrastructure (Facilitator)
- **Agent use**: Protocol-level agent support, consensus participation
- **On-chain**: Validator operations, cross-shard coordination
- **Relevance**: Agent protocol layer — if agents need custom consensus or fast-path access, this is where it lives
- **Stack**: Rust, libp2p, RocksDB

### meme-grid-game

- **Role**: Gamified DeFi (Facilitator + Risk Taker)
- **Agent use**: Grid placement agents, market-making bots
- **On-chain**: Grid positions, token mechanics
- **Reputation**: Game performance metrics
- **Status**: Concept phase

### wen-dinos

- **Role**: NFT / Community (Facilitator)
- **Agent use**: Community management agents, trait-based trading agents
- **On-chain**: NFT ownership, trait metadata
- **Reputation**: Community contribution scores
- **Status**: Concept phase

---

## 9. What's Built vs. What's Needed

### ✅ Built

| Component | Project | Status |
|-----------|---------|--------|
| Escrow blueprint | guild-saas | Scrypto component deployed |
| Manifest builders | guild-saas, auto-trader | TypeScript utilities |
| Trading bot | auto-trader-xrd | Running (deviation bug) |
| Dashboard stub | guild-saas | Next.js shell |
| Auto-trader core | auto-trader-xrd | Signal → execute pipeline |
| rdx-cli | xStelea/radix-web3.js | v0.2.0, x402 + Subintents |
| MCP servers | xStelea | attos-world, sbor-ez-mode |
| ROLA auth | xStelea/gateway-ez-mode | Pattern established |
| Multisig orchestrator | xStelea/multisig | Stokenet, Rust/Axum |

### ❌ Missing — Critical Path

| Component | Project | Priority | Notes |
|-----------|---------|----------|-------|
| `manifest-marketplace.ts` | guild-saas | **P0** | Core marketplace transaction manifests |
| Bot watcher rewrite | guild-saas | **P0** | Current bot architecture needs agent-based rewrite |
| Postgres persistence | guild-saas | **P0** | Replace in-memory state with durable storage |
| Agent Registry blueprint | shared | **P1** | Scrypto: badge NFT, metadata, deposit |
| AgentAccount blueprint | shared | **P1** | Scrypto: restricted sends, fast path, badge auth |
| Reputation oracle | shared | **P1** | Off-chain compute + on-chain commitment |
| rdx-cli integration | guild-saas | **P2** | Use rdx-cli for manifest building + x402 payments |
| Deviation mode fix | auto-trader-xrd | **P0** | Execute at oracle price, 2% slippage tolerance |
| Agent-to-agent protocol | shared | **P2** | Communication standard for Radix agents |
| Vercel AI SDK tools | guild-saas | **P1** | Custom Radix tools for AI SDK |

### Build Order (Recommended)

1. **Fix auto-trader deviation** (quick win, P0)
2. **manifest-marketplace.ts** (unblocks guild-saas core flow)
3. **Postgres persistence** (durability before scaling)
4. **Bot watcher → agent rewrite** (architecture upgrade)
5. **AgentAccount blueprint** (enables agent economy)
6. **Agent Registry** (identity layer)
7. **Reputation oracle** (quality layer)
8. **rdx-cli + x402 integration** (payment layer)
9. **Vercel AI SDK Radix tools** (developer experience)
10. **Agent-to-agent protocol** (network effects)

---

## Appendix A: xStelea Repository Map

All repos cloned to `~/.archon/workspaces/xstelea/`

```
xstelea/
├── radix-web3.js/          # Core SDK monorepo (rdx-cli, agent-toolkit, x402)
├── x402/                   # Radix payment protocol fork
├── radix-vaults/           # Full-stack multisig vault app
├── multisig/               # Rust multisig orchestrator
├── radix-context/          # AI agent knowledge base (20+ docs)
├── awesome-radix-mcp-servers/ # MCP server collection
├── gateway-ez-mode/        # Gateway API helpers + SBOR parsing
├── typescript-radix-engine-toolkit/ # Enhanced RET wrapper
├── scripts/                # Workflow automation
├── helpers/                # Zsh keybindings
├── radix-dapp-toolkit/     # RDT fork
├── sargon/                 # Wallet lib fork
├── radix-connect-webrtc/   # Wallet relay fork
├── eliza/                  # ElizaOS agent framework fork
├── eliza-starter/          # ElizaOS quickstart fork
├── goat/                   # GOAT SDK fork (Radix adapter)
├── a2a-agent-coder/        # Agent-to-agent coder fork
├── sandcastle/             # Sandboxed coding agent fork
├── consultation_v2/        # Governance dApp fork
├── codeguide-starter-pro/  # Template project
├── custom-instructions/    # LLM instruction sets
├── conventional-commit-types/ # Commit emoji types
└── radix-mofos/            # NFT project (mostly empty)
```

## Appendix B: Key Links

- **Radix Gateway API**: https://babylon-gateway.radixdlt.com
- **Radix Engine Toolkit**: https://github.com/radixdlt/radix-engine-toolkit
- **radix-web3.js**: https://github.com/xstelea/radix-web3.js
- **x402 Protocol**: https://github.com/coinbase/x402
- **GOAT SDK**: https://github.com/goat-sdk/goat
- **Vercel AI SDK**: https://sdk.vercel.ai
- **ElizaOS**: https://github.com/elizaOS/eliza
- **hyperscale-rs**: https://github.com/hyperscalers/hyperscale-rs
- **hyperscale-rs fork**: https://github.com/bigdevxrd/hyperscale-rs

## Appendix C: Glossary

| Term | Definition |
|------|-----------|
| **Badge** | Radix native resource used for authentication/authorization (replaces EVM's msg.sender) |
| **Manifest** | Declarative transaction intent describing resource movements |
| **Component** | Instantiated Scrypto blueprint with state (replaces EVM smart contract) |
| **Subintent** | Partial transaction that can be composed with other intents |
| **x402** | HTTP payment protocol (402 Payment Required) adapted for Radix |
| **ROLA** | Radix Off-Ledger Authentication — wallet-signed challenges |
| **Xi'an** | Next-gen Radix consensus (sharded, high throughput) |
| **Fast Path** | Xi'an single-shard consensus (sub-second finality) |
| **SBOR** | Scrypto Binary Object Representation (serialization format) |
| **RET** | Radix Engine Toolkit (WASM-based programmatic access) |
| **MCP** | Model Context Protocol (AI tool integration standard) |
| **RAP/1** | Radix Agent Protocol v1 (proposed in radix-web3.js) |
