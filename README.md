# Bitcoin Mining Pool Investigator

A Python tool that connects to Bitcoin mining pools via the Stratum protocol to investigate block templates and extract payout addresses from coinbase transactions.

## Features

- 🔌 **Stratum Protocol Support** - Connects to mining pools using the standard Stratum v1 protocol
- 🔒 **SSL/TLS Support** - Works with both plain TCP and SSL-encrypted connections
- 📊 **Coinbase Transaction Parsing** - Decodes and analyzes the coinbase transaction from mining jobs
- 💰 **Payout Address Extraction** - Identifies all payout addresses and their allocation percentages
- 🏷️ **Multiple Address Formats** - Supports P2PKH, P2SH, P2WPKH, P2WSH, and P2TR (Taproot) addresses

## How It Works

```
┌─────────────┐     Stratum Protocol      ┌─────────────┐
│   Pool      │◄─────────────────────────►│   Mining    │
│ Investigator│   1. mining.subscribe     │    Pool     │
│             │   2. mining.authorize     │             │
│             │   3. mining.notify (job)  │             │
└─────────────┘                           └─────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────┐
│              Coinbase Transaction                    │
├─────────────────────────────────────────────────────┤
│  coinbase1 + extranonce1 + extranonce2 + coinbase2  │
│                        │                             │
│                        ▼                             │
│              Parse Transaction Outputs               │
│                        │                             │
│                        ▼                             │
│              Extract Payout Addresses                │
└─────────────────────────────────────────────────────┘
```

## Installation

```bash
# Clone the repository
git clone https://github.com/WantClue/pool-investigator.git
cd pool-investigator

# No external dependencies required - uses only Python standard library
python3 investogator.py
```

## Usage

### Interactive Mode

Run the tool and follow the prompts:

```bash
python3 investogator.py
```

```
======================================================================
  Bitcoin Mining Pool Investigator
  Extracts payout addresses from pool block templates
======================================================================

Enter pool host/URL (supports stratum+tcp://, stratum+ssl://, stratum+tls://, or just hostname)
Examples:
  - stratum+tcp://pool.example.com
  - stratum+ssl://pool.example.com
  - stratum+tls://pool.example.com
  - pool.example.com
  - pool.example.com:3333 (with port)

Pool Host: stratum+tcp://74.207.253.18

Enter pool port (default: 3333)
Port [3333]: 3333

Enter worker name (usually your BTC address for anonymous mining pools)
Worker: bc1qyouraddresshere
```

### Supported URL Formats

| Format | Description |
|--------|-------------|
| `stratum+tcp://host:port` | Plain TCP connection |
| `stratum+ssl://host:port` | SSL/TLS encrypted connection |
| `stratum+tls://host:port` | SSL/TLS encrypted connection (alias) |
| `stratum://host:port` | Plain TCP (alias) |
| `host:port` | Plain TCP |
| `host` | Plain TCP on default port 3333 |

## Output

### Console Output

The tool displays detailed progress and results:

```
[✓] Connected successfully!
[✓] Subscribed!
[✓] Authorized!
[✓] Found mining.notify job!

======================================================================
  PAYOUT ADDRESSES
======================================================================
  [0] 37iU9NjhdzGt8NbaKiTwvuh72HG
      Value: 0.03133846 BTC (1.00%)

  [1] bc1q99n5gtdzusnadbasdalywpmwzalyhhgzsgsa7w20d
      Value: 0.03133846 BTC (1.00%)

  [2] bc1q99n5gtdzusnadbasdalywpmwzalyhhgzsgsa7w20d
      Value: 3.07116908 BTC (98.00%)
```

### JSON Output

Results are saved to `pool_investigation.json`:

```json
{
  "pool_url": "stratum+tcp://120.120.120.120",
  "host": "120.120.120.120",
  "port": 54321,
  "ssl": false,
  "worker": "bc1q99n5gtdzusnadbasdalywpmwzalyhhgzsgsa7w20d",
  "connected": true,
  "subscribed": true,
  "authorized": true,
  "mining_job": {
    "job_id": "1",
    "prevhash": "...",
    "coinbase1": "...",
    "coinbase2": "...",
    "merkle_branches": [...],
    "version": "20000000",
    "nbits": "1701d936",
    "ntime": "692766b9",
    "clean_jobs": true
  },
  "coinbase_analysis": {
    "version": 2,
    "is_segwit": false,
    "output_count": 4,
    "outputs": [...],
    "total_output_btc": 3.133846
  },
  "payout_addresses": [
    {
      "address": "37iU9NjhdzGt8NbaKiTwvuh72HG",
      "value_btc": 0.03133846,
      "percentage": 1.0
    },
    {
      "address": "bc1q99n5gtdzusnadbasdalywpmwzalyhhgzsgsa7w20d",
      "value_btc": 3.10250754,
      "percentage": 99.0
    }
  ]
}
```

## Understanding the Output

### Payout Addresses

The coinbase transaction in a block template specifies where the block reward goes. Common scenarios:

| Output Type | Description |
|-------------|-------------|
| **Pool Fee Address** | Usually a fixed address owned by the pool operator |
| **Miner Reward Address** | The worker address provided during authorization |
| **OP_RETURN** | Witness commitment data (non-spendable, 0 BTC) |

### Address Types Supported

| Prefix | Type | Description |
|--------|------|-------------|
| `1...` | P2PKH | Legacy Pay-to-Public-Key-Hash |
| `3...` | P2SH | Pay-to-Script-Hash |
| `bc1q...` (42 chars) | P2WPKH | Native SegWit |
| `bc1q...` (62 chars) | P2WSH | Native SegWit Script Hash |
| `bc1p...` | P2TR | Taproot |
| `OP_RETURN:...` | Null Data | Unspendable (witness commitment) |

## Technical Details

### Stratum Protocol Flow

1. **Connect** - Establish TCP/SSL connection to the pool
2. **Subscribe** - `mining.subscribe` to receive job notifications
3. **Authorize** - `mining.authorize` with worker credentials
4. **Receive Job** - Pool sends `mining.notify` with block template
5. **Parse Coinbase** - Reconstruct and decode the coinbase transaction

### Coinbase Transaction Structure

```
┌──────────────────────────────────────────────────────┐
│                 Coinbase Transaction                  │
├──────────┬──────────┬───────────┬──────────┬────────┤
│ Version  │  Inputs  │  Outputs  │ Witness  │Locktime│
│ (4 bytes)│  (var)   │   (var)   │  (var)   │(4 bytes│
└──────────┴──────────┴───────────┴──────────┴────────┘
                            │
                            ▼
               ┌────────────────────────┐
               │    Each Output:        │
               │  • Value (8 bytes)     │
               │  • ScriptPubKey (var)  │
               │    └─► Bitcoin Address │
               └────────────────────────┘
```

## Use Cases

- 🔍 **Pool Analysis** - Investigate how pools distribute block rewards
- 🧪 **Protocol Testing** - Test Stratum protocol implementations
- 📈 **Fee Analysis** - Understand pool fee structures
- 🔐 **Security Research** - Verify pool behavior and transparency

## Requirements

- Python 3.6+
- No external dependencies (uses only standard library)

## License

MIT License

## Disclaimer

This tool is for educational and research purposes only. Always respect the terms of service of mining pools you connect to.