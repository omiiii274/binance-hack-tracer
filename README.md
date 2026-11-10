# Binance Hack Tracer — Follow the Money

An on-chain investigation tool that starts from the 628 wallet addresses the FBI linked to the
29 October 2026 Binance hack (alert of 31 Oct 2026), follows the stolen funds hop by hop across
Bitcoin and Ethereum, and flags the moment funds reach a point where they can be frozen
(USDT/USDC, a labelled exchange, a bridge or swap service).

Read-only: it only reads public blockchain data. It never sends, signs or interacts with any wallet.

## What I found (first full scan, 10 November 2026)

- **All 18,270.20 stolen BTC are still untouched.** The 19 FBI-listed Bitcoin addresses hold
  exactly what they received (17 × 1,000 BTC, plus 832.50 and 437.70 BTC). Not one output has been spent.
- **Large ETH holdings are also parked.** For example, one FBI-listed address received 195,460 ETH
  on 29 Oct 2026 at 20:38 UTC and has never sent anything out.
- **The hackers' wallets are themselves being targeted by address-poisoning bots.** The tracer saw
  dust transfers from lookalike addresses (e.g. `0x8534…c3d4` imitating `0x8532…43D4`) and 24 spoofed
  transfers from 8 fake token contracts named "ETH" (some using lookalike Unicode such as `Е⁯ΤН⁯`)
  to lookalike addresses. A naive tracer counts these as real flows; this one filters them out.
- **Two new wallets outside the FBI list were identified** that received funds from an FBI-listed
  address after the alert. They were verified and reported to the FBI (IC3) and are deliberately
  not published here.

### Lessons from building it
- Free APIs fail quietly: a rate-limit reply looked like "no transactions" until the tracer was
  changed to treat it as an error and retry.
- Spam buries history: one wallet had 641 transactions, almost all dust, so the tracer now reads
  the full history instead of only the newest pages.
- Only the real USDT and USDC contracts are trusted; any other token is ignored.

## Files

| File | What it is |
|---|---|
| `binance_hack_addresses.csv` | The 628 FBI addresses (608 ETH, 19 BTC, 1 SOL), verified against the FBI page |
| `extract_fbi_addresses.py` | Rebuilds that CSV from the FBI page if the list is updated |
| `tracer.py` | The tracer |
| `labels.csv` | Known freezable points. Add exchange or bridge addresses here as you find them |

## Run it

```bash
pip install requests
python tracer.py init          # load the FBI addresses
python tracer.py scan          # first pass: maps the existing theft flow silently (takes a while)
python tracer.py watch --every 10   # keep watching; alerts print as funds move
python tracer.py report        # write the outputs below
python tracer.py status        # quick summary
```

Keep all files in one folder. With an Etherscan key the first scan takes about 15–25 minutes.
Stopping and restarting is safe: progress is saved in `tracer.db`, and addresses where an API call
failed are retried on the next pass.

Recommended: a free Etherscan API key. Without one, the free Blockscout API rate-limits heavily.

```bash
export ETHERSCAN_API_KEY=your_key_here   # never commit this to the repo
```

## How it works

1. **Seed:** the FBI addresses are hop 0.
2. **Map history (silent):** the first time an address is scanned, its past outgoing transactions are
   recorded without alerts. This rebuilds where the money has already gone.
3. **Follow:** any destination receiving more than the threshold (0.05 BTC, 0.5 ETH, $5,000 in
   stablecoins) is added to the watchlist as the next hop, up to 4 hops.
4. **Flag freeze points:** if funds reach USDT/USDC, an address in `labels.csv`, or an Ethereum
   address whose public explorer tag mentions an exchange, bridge or swap service, a **HIGH** alert
   is raised and that branch stops (the service is now the one who can act).
5. **Live:** after the first pass, every new outflow raises an alert.

Bitcoin "change" outputs (money sent back to the sender) are skipped. Dust is ignored.

## Outputs

- `alerts.csv` — every alert with a transaction link
- `report_for_ic3.md` — freeze-point hits and newly discovered addresses, ready to verify and report
- `edges.csv`, `nodes.csv` — the money-flow graph; open in Gephi or load with NetworkX

## Limits (worth stating honestly)

- Exchange detection on Bitcoin depends on `labels.csv`; there are no free public BTC labels.
- Ethereum internal (contract-to-contract) transfers and cross-chain hops are not followed
  automatically. When funds hit a bridge or THORChain, follow the other chain manually.
- Professional firms (Elliptic, Chainalysis, TRM Labs) have far larger label databases. This is a
  research and learning tool, not a replacement.

