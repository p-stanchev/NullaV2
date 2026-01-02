# Nulla Tokenomics

## Overview

Nulla implements a deflationary token economics model similar to Bitcoin, with controlled emission, halvings, and tail emission for long-term network sustainability.

## Token Unit

### NULLA (Base Unit)
- **1 NULLA** = 100,000,000 atoms
- **Smallest unit**: 1 atom (0.00000001 NULLA)
- **Decimal places**: 8 (same as Bitcoin satoshis)
- **Ticker**: NULLA
- **Atomic unit name**: atoms

### Examples
```
1.00000000 NULLA = 100,000,000 atoms
0.50000000 NULLA =  50,000,000 atoms
0.00010000 NULLA =      10,000 atoms (minimum transaction fee)
0.00000001 NULLA =           1 atom  (smallest unit)
```

## Block Reward Schedule

### Initial Emission
- **Genesis reward**: 8.00000000 NULLA per block (800,000,000 atoms)
- **Target block time**: 120 seconds (2 minutes)
- **Blocks per day**: ~720 blocks
- **Daily emission (initial)**: ~5,760 NULLA

### Halving Schedule

Nulla implements Bitcoin-style halvings to create a deflationary supply curve:

| Halving # | Block Range | Reward (NULLA) | Duration | Total Minted |
|-----------|-------------|----------------|----------|--------------|
| 0 (Genesis) | 0 - 209,999 | 8.00000000 | ~292 days | 1,680,000 |
| 1 | 210,000 - 419,999 | 4.00000000 | ~292 days | 840,000 |
| 2 | 420,000 - 629,999 | 2.00000000 | ~292 days | 420,000 |
| 3 | 630,000 - 839,999 | 1.00000000 | ~292 days | 210,000 |
| 4 | 840,000 - 1,049,999 | 0.50000000 | ~292 days | 105,000 |
| 5 | 1,050,000 - 1,259,999 | 0.25000000 | ~292 days | 52,500 |
| 6 | 1,260,000 - 1,469,999 | 0.12500000 | ~292 days | 26,250 |
| 7 | 1,470,000+ | 0.06250000 (tail) | Forever | Infinite |

**Halving interval**: Every 210,000 blocks (~292 days / ~9.7 months)

**Note**: Unlike Bitcoin which has 64 halvings before reaching 0 reward, Nulla stops halving at 0.0625 NULLA and maintains this as perpetual tail emission.

### Tail Emission

After 7 halvings (block 1,470,000 / ~5.6 years), Nulla enters **tail emission** mode:

- **Tail emission rate**: 0.0625 NULLA per block (6,250,000 atoms)
- **Purpose**: Ensure perpetual miner incentives for network security
- **Annual inflation**: ~0.18% (decreasing as supply grows)
- **Rationale**: Bitcoin's eventual 0 block reward could compromise security; tail emission ensures miners are always compensated

## Maximum Supply

### Pre-Tail Emission
```
Total supply before tail emission:
= 1,680,000 + 840,000 + 420,000 + 210,000 + 105,000 + 52,500 + 26,250
= 3,333,750 NULLA
```

### With Tail Emission
- **Capped supply**: No hard cap due to tail emission
- **Effective supply**: ~3.35 million NULLA + perpetual 0.0625 NULLA/block
- **Long-term inflation**: Approaches 0% as total supply grows

### Comparison to Bitcoin
| Metric | Bitcoin | Nulla |
|--------|---------|-------|
| Max supply | 21,000,000 BTC | ~3,335,000 NULLA + tail |
| Block time | 600s (10 min) | 120s (2 min) |
| Halving interval | 210,000 blocks (~4 years) | 210,000 blocks (~9.7 months) |
| Decimal places | 8 (satoshis) | 8 (atoms) |
| Tail emission | None (0 reward eventually) | 0.0625 NULLA perpetual |
| Genesis reward | 50 BTC | 8 NULLA |

## Transaction Fees

### Fee Structure
- **Minimum fee**: 0.0001 NULLA (10,000 atoms) per transaction
- **Fee calculation**: `fee = total_inputs - total_outputs`
- **Fee recipient**: Miner who includes the transaction in a block
- **Fee validation**: Enforced at mempool, RPC, and block validation

### Fee Economics
```
Transaction anatomy:
- Inputs:  10.00000000 NULLA (from UTXOs)
- Outputs:  9.99990000 NULLA (to recipient)
- Fee:      0.00010000 NULLA (to miner)
```

### Spam Prevention
- Minimum fee prevents transaction spam
- Free transactions are rejected by the network
- Mempool prioritizes higher-fee transactions (future upgrade)

### Long-term Fee Market
As block rewards decrease:
- Transaction fees become increasingly important for miner revenue
- Users compete with higher fees during network congestion
- Fee market develops naturally (like Bitcoin)

## Coinbase Transaction

### Structure
Every block contains exactly one **coinbase transaction** as the first transaction:

```
Coinbase transaction (always index 0):
- Inputs: None (generated from nothing)
- Outputs: Block reward + transaction fees
- Recipient: Miner's address (specified via --miner-address)
```

### Example Coinbase
```
Block height: 100
Block reward: 8.00000000 NULLA
Transaction fees: 0.00050000 NULLA
Total coinbase: 8.00050000 NULLA
```

### Coinbase Maturity
- **Maturity period**: 100 blocks (~200 minutes / ~3.3 hours)
- **Rationale**: Prevents spending coinbase UTXOs before chain reorganization risk is minimal
- **Implementation**: Transactions attempting to spend immature coinbase outputs are rejected

## Difficulty Adjustment

### Algorithm
Nulla uses Bitcoin-style difficulty adjustment:

- **Adjustment interval**: Every 60 blocks
- **Target block time**: 120 seconds (2 minutes)
- **Target adjustment time**: 7,200 seconds (60 blocks × 120s = 2 hours)
- **Maximum adjustment**: 4x per interval (prevents extreme swings)

### Formula
```
new_target = old_target × (actual_time / target_time)
new_target = min(new_target, old_target × 4)  // Cap at 4x increase
new_target = max(new_target, old_target / 4)  // Cap at 4x decrease
```

### Difficulty Dynamics
- **Hashrate increases** → Blocks found faster → Difficulty increases
- **Hashrate decreases** → Blocks found slower → Difficulty decreases
- **Result**: Self-adjusting network that maintains ~2 minute block times

## Inflation Schedule

### Annual Inflation Rates (Approximate)

| Year | Blocks | Supply (NULLA) | Annual Emission | Inflation % |
|------|--------|----------------|-----------------|-------------|
| 1 | 262,800 | 1,680,000 | 2,102,400 | 125% |
| 2 | 525,600 | 2,522,400 | 1,051,200 | 42% |
| 3 | 788,400 | 3,048,000 | 525,600 | 17% |
| 4 | 1,051,200 | 3,310,800 | 262,800 | 8% |
| 5 | 1,314,000 | 3,442,200 | 131,400 | 4% |
| 10 | 2,628,000 | 3,333,750 | 45,000 | 1.3% |
| 20 | 5,256,000 | 3,333,750 | 45,000 | 0.7% |
| 50+ | 13,140,000+ | Growing | 45,000 | ~0.18% → 0% |

**Note**: Inflation approaches 0% over time as supply grows while tail emission remains constant.

## Economic Security

### Finality
- **Confirmation depth**: 30 blocks recommended (~60 minutes)
- **Maximum reorg depth**: 30 blocks (security limit)
- **Deep reorg protection**: Reorganizations deeper than 30 blocks are rejected
- **Rationale**: 30 blocks provides practical finality while preventing DoS attacks

### Security Budget
```
Year 1 security budget:
- Block rewards: ~2,102,400 NULLA/year
- Transaction fees: Variable (grows with adoption)
- Total miner revenue: Block rewards + fees

Assuming:
- $1 per NULLA (hypothetical)
- 5% transaction fees
- Annual security budget: ~$2.2 million (grows with price and fees)
```

### Long-term Security
After all halvings:
- **Tail emission**: 45,000 NULLA/year perpetually
- **Transaction fees**: Expected to grow as primary miner incentive
- **Combined revenue**: Maintains miner incentives indefinitely
- **Advantage over Bitcoin**: No future point where rewards = 0

## Distribution Model

### Fair Launch
- **No pre-mine**: 0 NULLA existed before genesis block
- **No ICO**: No token sale or fundraising
- **No founder allocation**: All NULLA mined through PoW
- **Pure PoW distribution**: 100% of supply from mining

### Mining Distribution
```
Year 1: ~1,680,000 NULLA (50% of max supply before tail)
Year 2: ~840,000 NULLA (25% of max supply before tail)
Year 3: ~420,000 NULLA (12.5% of max supply before tail)
Year 4: ~210,000 NULLA (6.25% of max supply before tail)
```

**80% of pre-tail supply mined in first 2 years** - rewards early miners while maintaining long-term emission.

## Use Cases

### Medium of Exchange
- Fast confirmations (~2 minutes)
- Low minimum fees (0.0001 NULLA)
- Suitable for everyday transactions

### Store of Value
- Deflationary supply (decreasing emission)
- Halving schedule reduces inflation over time
- Tail emission prevents long-term security issues

### Network Security
- Proof-of-Work consensus
- Miner incentives via block rewards + fees
- Perpetual security budget via tail emission

## Comparison to Other Chains

| Feature | Bitcoin | Monero | Nulla |
|---------|---------|--------|-------|
| Max Supply | 21M BTC | Infinite (tail) | ~3.35M + tail |
| Block Time | 10 min | 2 min | 2 min |
| Decimal Places | 8 | 12 | 8 |
| Tail Emission | No | Yes (0.6 XMR/min) | Yes (0.0625 NULLA/block) |
| Halving | Every 4 years | Smooth decay | Every 9.7 months |
| Privacy | Transparent | Private | Transparent + Dandelion++ |
| Finality | 6 blocks | 10 blocks | 30 blocks |

## Economic Rationale

### Why 8 NULLA Genesis Reward?
- **Smaller total supply**: Creates scarcity (~3.35M vs Bitcoin's 21M)
- **Higher per-unit value**: Psychological pricing advantage
- **Faster distribution**: Halving every ~9.7 months accelerates early adoption

### Why 2-Minute Block Times?
- **User experience**: Faster confirmations than Bitcoin (2 min vs 10 min)
- **Network efficiency**: 5x more frequent blocks = better UX
- **Security trade-off**: Acceptable given modern network speeds

### Why Tail Emission?
- **Perpetual security**: Ensures miners are always compensated
- **Inflation approaches 0%**: Fixed emission becomes negligible as supply grows
- **Avoids Bitcoin's security budget problem**: No future point where rewards = 0

### Why 30-Block Finality?
- **Practical security**: ~60 minutes provides reasonable finality
- **DoS protection**: Prevents deep reorg attacks
- **User experience**: Balances security and usability

## Future Considerations

### Fee Market Development
As block rewards decrease:
1. Transaction fees become primary miner revenue
2. Fee market develops naturally during congestion
3. Users compete with higher fees for priority
4. Mempool prioritization by fee (future upgrade)

### Deflationary Pressure
With tail emission:
- Lost coins create deflationary pressure
- Natural deflation offsets tail emission
- Long-term stable/deflationary economics

### Economic Upgrades
Potential future improvements:
- Dynamic block size (increased throughput)
- Fee estimation algorithm (better UX)
- Lightning Network (Layer 2 scaling)
- Fee market optimizations

## Summary

Nulla's tokenomics are designed for:
- ✅ **Fair distribution** (no pre-mine, pure PoW)
- ✅ **Deflationary supply** (halvings + small max supply)
- ✅ **Long-term security** (tail emission ensures perpetual miner incentives)
- ✅ **User experience** (fast blocks, low fees)
- ✅ **Economic sustainability** (balanced inflation approaching 0%)

The combination of Bitcoin's proven halving model, Monero's tail emission for perpetual security, and fast 2-minute blocks creates a sustainable economic model for long-term network health.
