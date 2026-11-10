"""
Follow-the-money tracer for the Binance hack (29 Oct 2026).

Starts from the FBI-published addresses (binance_hack_addresses.csv), watches them for
outgoing transactions, and automatically adds every address the money moves to
(up to a depth limit) to the watchlist. When funds reach a place where they can be
frozen (USDT/USDC, a labelled exchange, a bridge/swap service) it raises a HIGH alert.

Only public blockchain data is read. Nothing is ever sent, signed or touched.

Usage:
    pip install requests
    python tracer.py init                 # load FBI addresses into the database
    python tracer.py scan                 # one pass (first pass = silent history backfill)
    python tracer.py watch --every 10     # keep scanning every 10 minutes (Ctrl+C to stop)
    python tracer.py report               # write alerts + IC3-ready report + graph files
    python tracer.py status               # quick summary

Optional: set ETHERSCAN_API_KEY to use Etherscan instead of the free Blockscout API.
"""

import argparse
import csv
import json
import os
import sqlite3
import sys
import time
from datetime import datetime, timezone

DB_FILE = "tracer.db"
SEED_CSV = "binance_hack_addresses.csv"
LABELS_CSV = "labels.csv"

# ---- tuning -------------------------------------------------------------------
MAX_DEPTH = 4                 # how many hops away from FBI addresses we follow
MAX_WATCHLIST = 5000          # safety cap so the graph can't explode
MIN_FOLLOW = {                # ignore dust; only follow meaningful amounts
    "BTC": 0.05,
    "ETH": 0.5,
    "TOKEN_USD": 5000,        # stablecoins (USD value ≈ token amount)
}
REQUEST_PAUSE = 0.4           # seconds between API calls (Etherscan free tier enforces ~3/sec)
BACKFILL_PAGES = 10           # pages of history per address on the first pass (ETH: 1000 tx/page)

# Freezable stablecoins: issuer can freeze these. (Ethereum mainnet contracts)
FREEZABLE_TOKENS = {
    "0xdac17f958d2ee523a2206206994597c13d831ec7": "USDT (Tether) - freezable",
    "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": "USDC (Circle) - freezable",
}
STABLE_SYMBOLS = {"USDT", "USDC", "DAI", "USD1", "RLUSD", "FDUSD", "PYUSD"}

# Words that, if they appear in an explorer's public name/tag for an address,
# mean "this is a service where funds can be stopped".
SERVICE_KEYWORDS = [
    "binance", "coinbase", "kraken", "okx", "okex", "bybit", "kucoin", "huobi", "htx",
    "gate.io", "gateio", "bitfinex", "bitget", "mexc", "crypto.com", "bitstamp",
    "gemini", "upbit", "bithumb", "exchange", "thorchain", "bridge", "swap",
    "changenow", "fixedfloat", "sideshift", "simpleswap", "tornado", "mixer",
]

UA = {"User-Agent": "binance-hack-tracer/1.0 (public data research)"}


# =============================================================================
# Database
# =============================================================================

def db():
    con = sqlite3.connect(DB_FILE)
    con.row_factory = sqlite3.Row
    con.executescript("""
    CREATE TABLE IF NOT EXISTS addresses(
        chain TEXT, address TEXT, depth INT, parent TEXT, via_tx TEXT,
        label TEXT, terminal INT DEFAULT 0, backfilled INT DEFAULT 0,
        added_at TEXT, PRIMARY KEY(chain, address));
    CREATE TABLE IF NOT EXISTS seen_tx(chain TEXT, txid TEXT, address TEXT,
        PRIMARY KEY(chain, txid, address));
    CREATE TABLE IF NOT EXISTS edges(
        chain TEXT, txid TEXT, src TEXT, dst TEXT, asset TEXT, amount REAL,
        time TEXT, PRIMARY KEY(chain, txid, src, dst, asset));
    CREATE TABLE IF NOT EXISTS alerts(
        id INTEGER PRIMARY KEY AUTOINCREMENT, created TEXT, level TEXT, chain TEXT,
        txid TEXT, src TEXT, dst TEXT, asset TEXT, amount REAL, tx_time TEXT,
        reason TEXT, UNIQUE(chain, txid, src, dst, asset));
    """)
    return con


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def norm(chain, addr):
    return addr.lower() if chain == "ethereum" else addr


# =============================================================================
# Labels (user-editable labels.csv + explorer public tags)
# =============================================================================

def load_labels():
    labels = {}
    if os.path.exists(LABELS_CSV):
        with open(LABELS_CSV, encoding="utf-8") as f:
            for row in csv.DictReader(f):
                if row.get("address"):
                    labels[(row["chain"].strip(), norm(row["chain"].strip(), row["address"].strip()))] = row["label"].strip()
    return labels


def service_hit(text):
    t = (text or "").lower()
    return next((k for k in SERVICE_KEYWORDS if k in t), None)


# =============================================================================
# Blockchain data sources (all read-only, public)
# =============================================================================

class Sources:
    """Real API calls. Swapped out for fake data in tests."""

    def __init__(self):
        import requests
        self.s = requests.Session()
        self.s.headers.update(UA)
        self.ethkey = os.environ.get("ETHERSCAN_API_KEY")
        self._tag_cache = {}
        self.errors = 0  # failed requests; an address with a failure is retried next pass

    def _get(self, url, params=None, tries=4):
        for i in range(tries):
            try:
                time.sleep(REQUEST_PAUSE)
                r = self.s.get(url, params=params, timeout=30)
                if r.status_code == 429:
                    raise RuntimeError("rate limited (429)")
                r.raise_for_status()
                return r.json()
            except Exception as e:
                print(f" [retry {i + 1}: {str(e)[:40]}]", end="", flush=True)
                if i == tries - 1:
                    print(f" request failed: {url}", flush=True)
                    self.errors += 1
                    return None
                time.sleep(10 * (i + 1))  # back off properly so the API lets us in again
        self.errors += 1
        return None

    # ---------- Bitcoin via mempool.space ----------
    def btc_txs(self, addr, pages=1):
        out, last = [], None
        for _ in range(pages):
            url = f"https://mempool.space/api/address/{addr}/txs" + (f"/chain/{last}" if last else "")
            data = self._get(url)
            if not data:
                break
            out.extend(data)
            confirmed = [t for t in data if t.get("status", {}).get("confirmed")]
            if len(data) < 25 or not confirmed:
                break
            last = confirmed[-1]["txid"]
        return out

    # ---------- Ethereum via Etherscan (key) or Blockscout (free) ----------
    def _eth_api(self, params):
        if self.ethkey:
            p = dict(params, chainid=1, apikey=self.ethkey)
            data = self._get("https://api.etherscan.io/v2/api", p)
        else:
            time.sleep(1.0)  # free Blockscout limit is strict without a key
            data = self._get("https://eth.blockscout.com/api", params)
        if not data:
            return []  # _get already counted the error
        if isinstance(data.get("result"), list):
            return data["result"]
        # status 0 with a non-list result = rate limit or API error, NOT "no transactions"
        msg = str(data.get("message", "")) + " " + str(data.get("result", ""))
        if "invalid api key" in msg.lower():
            sys.exit("\n\nEtherscan says the API key is invalid. Copy the real key from "
                     "etherscan.io -> API Keys, then run:\n"
                     "   export ETHERSCAN_API_KEY=<your real key>\n"
                     "Or remove it to use the slower free API:   unset ETHERSCAN_API_KEY")
        print(f" [API said: {msg.strip()[:60]}]", end="", flush=True)
        self.errors += 1
        time.sleep(15)
        return []

    def eth_txs(self, addr, pages=1):
        # Backfill reads the FULL history (spam/dust can bury old outflows), live passes read the newest 100.
        size = 1000 if pages > 1 else 100
        txs, toks = [], []
        more_tx = more_tok = True
        for page in range(1, pages + 1):
            base = {"module": "account", "address": addr, "page": page, "offset": size, "sort": "desc"}
            if more_tx:
                a = self._eth_api(dict(base, action="txlist"))
                txs += a
                more_tx = len(a) == size
            if more_tok:
                b = self._eth_api(dict(base, action="tokentx"))
                toks += b
                more_tok = len(b) == size
            if not (more_tx or more_tok):
                break
        return txs, toks

    def eth_tag(self, addr):
        """Public name/tags from Blockscout (e.g. 'Binance 14'). Cached."""
        if addr in self._tag_cache:
            return self._tag_cache[addr]
        data = self._get(f"https://eth.blockscout.com/api/v2/addresses/{addr}") or {}
        text = " ".join(str(v) for v in [
            data.get("name"),
            json.dumps(data.get("metadata") or {}),
            json.dumps(data.get("public_tags") or []),
        ])
        self._tag_cache[addr] = text
        return text

    # ---------- Solana via public RPC (activity alerts only) ----------
    def sol_sigs(self, addr):
        data = None
        try:
            time.sleep(REQUEST_PAUSE)
            r = self.s.post("https://api.mainnet-beta.solana.com", json={
                "jsonrpc": "2.0", "id": 1, "method": "getSignaturesForAddress",
                "params": [addr, {"limit": 50}]}, timeout=30)
            data = r.json().get("result")
        except Exception as e:
            print(f"    ! solana request failed ({e})")
            self.errors += 1
        return data or []


# =============================================================================
# Core logic
# =============================================================================

class Tracer:
    def __init__(self, con, src):
        self.con = con
        self.src = src
        self.labels = load_labels()
        self.new_alerts = 0

    # ----- helpers -----
    def watch_count(self):
        return self.con.execute("SELECT COUNT(*) FROM addresses").fetchone()[0]

    def label_for(self, chain, addr):
        lab = self.labels.get((chain, norm(chain, addr)))
        if lab:
            return lab
        if chain == "ethereum":
            hit = service_hit(self.src.eth_tag(addr))
            if hit:
                return f"explorer tag mentions '{hit}'"
        return None

    def add_address(self, chain, addr, depth, parent, txid, label=None, live=False):
        addr = norm(chain, addr)
        if self.con.execute("SELECT 1 FROM addresses WHERE chain=? AND address=?", (chain, addr)).fetchone():
            return False
        if self.watch_count() >= MAX_WATCHLIST:
            return False
        # live=True: found during live watching -> alert on everything it does from now on.
        # live=False: found while mapping history -> its own history is mapped silently first.
        self.con.execute(
            "INSERT INTO addresses(chain,address,depth,parent,via_tx,label,terminal,backfilled,added_at) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            (chain, addr, depth, parent, txid, label, 1 if label else 0, 1 if live else 0, now()))
        return True

    def edge(self, chain, txid, src, dst, asset, amount, t):
        self.con.execute("INSERT OR IGNORE INTO edges VALUES(?,?,?,?,?,?,?)",
                         (chain, txid, norm(chain, src), norm(chain, dst), asset, amount, t))

    def alert(self, level, chain, txid, src, dst, asset, amount, t, reason, silent):
        if silent:
            if level != "HIGH":
                return
            level = "PAST"  # history: funds already reached a freeze point - keep for the report, don't shout
            self.con.execute(
                "INSERT OR IGNORE INTO alerts(created,level,chain,txid,src,dst,asset,amount,tx_time,reason) "
                "VALUES(?,?,?,?,?,?,?,?,?,?)", (now(), level, chain, txid, src, dst, asset, amount, t, reason))
            return
        cur = self.con.execute(
            "INSERT OR IGNORE INTO alerts(created,level,chain,txid,src,dst,asset,amount,tx_time,reason) "
            "VALUES(?,?,?,?,?,?,?,?,?,?)",
            (now(), level, chain, txid, src, dst, asset, amount, t, reason))
        if cur.rowcount:
            self.new_alerts += 1
            mark = "🚨 HIGH" if level == "HIGH" else "•  move"
            print(f"\n      {mark} [{chain}] {amount:,.4f} {asset}  {src[:10]}… → {dst[:10]}…  ({reason})")

    def seen(self, chain, txid, addr):
        r = self.con.execute("SELECT 1 FROM seen_tx WHERE chain=? AND txid=? AND address=?",
                             (chain, txid, addr)).fetchone()
        if not r:
            self.con.execute("INSERT INTO seen_tx VALUES(?,?,?)", (chain, txid, addr))
        return bool(r)

    def handle_destination(self, chain, row, txid, dst, asset, amount, t, threshold, silent, forced_label=None):
        """Decide what happens to money arriving at `dst`."""
        src = row["address"]
        self.edge(chain, txid, src, dst, asset, amount, t)
        known = self.con.execute("SELECT 1 FROM addresses WHERE chain=? AND address=?",
                                 (chain, norm(chain, dst))).fetchone()
        if forced_label:
            label = forced_label
        elif known or amount < threshold:
            # Already watched, or dust: only the local labels file is checked (no slow web lookup).
            label = self.labels.get((chain, norm(chain, dst)))
        else:
            label = self.label_for(chain, dst)
        if label:
            self.add_address(chain, dst, row["depth"] + 1, src, txid, label=label, live=not silent)
            self.alert("HIGH", chain, txid, src, dst, asset, amount, t,
                       f"reached freezable point: {label}", silent)
            return
        if amount < threshold:
            return
        if row["depth"] + 1 > MAX_DEPTH:
            self.alert("INFO", chain, txid, src, dst, asset, amount, t, "moved beyond depth limit", silent)
            return
        added = self.add_address(chain, dst, row["depth"] + 1, src, txid, live=not silent)
        self.alert("INFO", chain, txid, src, dst, asset, amount, t,
                   "new hop - now watching" if added else "funds moved", silent)

    # ----- per chain -----
    def scan_btc(self, row, silent):
        addr = row["address"]
        txs = self.src.btc_txs(addr, pages=BACKFILL_PAGES if silent else 1)
        for tx in txs:
            txid = tx["txid"]
            if self.seen("bitcoin", txid, addr):
                continue
            ins = {v.get("prevout", {}).get("scriptpubkey_address") for v in tx.get("vin", [])}
            if addr not in ins:
                continue  # incoming, not an outflow
            t = tx.get("status", {}).get("block_time")
            t = datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%d %H:%M UTC") if t else "unconfirmed"
            for out in tx.get("vout", []):
                dst = out.get("scriptpubkey_address")
                if not dst or dst in ins:
                    continue  # change back to the sender
                self.handle_destination("bitcoin", row, txid, dst, "BTC", out.get("value", 0) / 1e8, t,
                                        MIN_FOLLOW["BTC"], silent)

    def scan_eth(self, row, silent):
        addr = row["address"]
        txs, toks = self.src.eth_txs(addr, pages=BACKFILL_PAGES if silent else 1)
        for tx in txs:
            if (tx.get("from") or "").lower() != addr or tx.get("isError") == "1":
                continue
            key = tx["hash"] + ":eth"
            if self.seen("ethereum", key, addr):
                continue
            amount = int(tx.get("value") or 0) / 1e18
            if amount == 0:
                continue  # contract call without ETH (token moves are handled below)
            t = datetime.fromtimestamp(int(tx["timeStamp"]), timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
            dst = (tx.get("to") or "").lower()
            if dst:
                self.handle_destination("ethereum", row, tx["hash"], dst, "ETH", amount, t,
                                        MIN_FOLLOW["ETH"], silent)
        for tk in toks:
            if (tk.get("from") or "").lower() != addr:
                continue
            key = f"{tk['hash']}:{tk.get('contractAddress')}:{tk.get('to')}:{tk.get('value')}"
            if self.seen("ethereum", key, addr):
                continue
            dec = int(tk.get("tokenDecimal") or 18)
            amount = int(tk.get("value") or 0) / (10 ** dec)
            sym = (tk.get("tokenSymbol") or "?").upper()
            contract = (tk.get("contractAddress") or "").lower()
            t = datetime.fromtimestamp(int(tk["timeStamp"]), timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
            dst = (tk.get("to") or "").lower()
            if contract not in FREEZABLE_TOKENS:
                # Unknown token contracts are ignored entirely. Scammers deploy fake tokens named
                # "ETH" / "USDT" (even with lookalike unicode) that emit fake transfers "from" a
                # victim address to lookalike addresses. Only the real USDT/USDC contracts count.
                continue
            if amount < 1:
                continue  # zero/dust transfers of real USDT/USDC are also a poisoning trick
            self.handle_destination("ethereum", row, tk["hash"], dst, sym, amount, t, 0, silent,
                                    forced_label=FREEZABLE_TOKENS[contract])

    def scan_sol(self, row, silent):
        addr = row["address"]
        for s in self.src.sol_sigs(addr):
            sig = s.get("signature")
            if not sig or self.seen("solana", sig, addr):
                continue
            t = s.get("blockTime")
            t = datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%d %H:%M UTC") if t else "?"
            self.alert("INFO", "solana", sig, addr, "?", "SOL-activity", 0, t,
                       "activity on FBI Solana address - check on Solscan", silent)

    # ----- one full pass -----
    def scan(self):
        rows = self.con.execute(
            "SELECT * FROM addresses WHERE terminal=0 ORDER BY depth, chain").fetchall()
        print(f"Scanning {len(rows)} addresses ({now()})")
        for i, row in enumerate(rows, 1):
            silent = not row["backfilled"]
            t0 = time.time()
            err0 = getattr(self.src, "errors", 0)
            print(f"  [{i}/{len(rows)}] {row['chain']} {row['address'][:12]}… "
                  f"{'(reading history)' if silent else ''}", end="", flush=True)
            # FBI seed addresses: history is the known theft flow -> map it silently.
            # Newly discovered hops: also backfill silently, then alert on anything new.
            try:
                if row["chain"] == "bitcoin":
                    self.scan_btc(row, silent)
                elif row["chain"] == "ethereum":
                    self.scan_eth(row, silent)
                elif row["chain"] == "solana":
                    self.scan_sol(row, silent)
            except Exception as e:
                print(f" error: {e}", flush=True)
                continue
            if getattr(self.src, "errors", 0) > err0:
                self.con.commit()
                print(" incomplete (API error) - will retry next pass", flush=True)
                continue
            self.con.execute("UPDATE addresses SET backfilled=1 WHERE chain=? AND address=?",
                             (row["chain"], row["address"]))
            self.con.commit()
            print(f" done in {time.time() - t0:.0f}s · watchlist {self.watch_count()}", flush=True)
        self.con.commit()
        print(f"Pass complete. New alerts: {self.new_alerts}. Watchlist: {self.watch_count()} addresses.")


# =============================================================================
# Commands
# =============================================================================

def cmd_init(con):
    if not os.path.exists(SEED_CSV):
        sys.exit(f"{SEED_CSV} not found. Put it next to this script.")
    n = 0
    with open(SEED_CSV, encoding="utf-8") as f:
        for r in csv.DictReader(f):
            a = norm(r["chain"], r["address"])
            cur = con.execute(
                "INSERT OR IGNORE INTO addresses(chain,address,depth,parent,via_tx,label,added_at) "
                "VALUES(?,?,0,'FBI list',NULL,NULL,?)", (r["chain"], a, now()))
            n += cur.rowcount
    con.commit()
    print(f"Loaded {n} FBI addresses. Next: python tracer.py scan")


EXPL_TX = {"bitcoin": "https://mempool.space/tx/{}", "ethereum": "https://etherscan.io/tx/{}",
           "solana": "https://solscan.io/tx/{}"}
EXPL_ADDR = {"bitcoin": "https://mempool.space/address/{}", "ethereum": "https://etherscan.io/address/{}",
             "solana": "https://solscan.io/account/{}"}


def cmd_report(con):
    alerts = con.execute("SELECT * FROM alerts ORDER BY level='HIGH' DESC, id").fetchall()
    with open("alerts.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["level", "chain", "tx_time", "asset", "amount", "from", "to", "reason", "tx_link"])
        for a in alerts:
            w.writerow([a["level"], a["chain"], a["tx_time"], a["asset"], a["amount"], a["src"], a["dst"],
                        a["reason"], EXPL_TX[a["chain"]].format(a["txid"])])

    # Graph files: edges.csv (Gephi / NetworkX) + nodes.csv
    with open("edges.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["Source", "Target", "chain", "asset", "amount", "time", "txid"])
        for e in con.execute("SELECT * FROM edges"):
            w.writerow([e["src"], e["dst"], e["chain"], e["asset"], e["amount"], e["time"], e["txid"]])
    with open("nodes.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["Id", "chain", "depth", "type", "label"])
        for n in con.execute("SELECT * FROM addresses"):
            kind = "FBI" if n["depth"] == 0 else ("freezable" if n["terminal"] else "hop")
            w.writerow([n["address"], n["chain"], n["depth"], kind, n["label"] or ""])

    # Human report for IC3 / exchanges: only HIGH alerts + new hops not on FBI list
    high = [a for a in alerts if a["level"] == "HIGH"]
    past = [a for a in alerts if a["level"] == "PAST"]
    hops = con.execute("SELECT * FROM addresses WHERE depth>0 ORDER BY depth, added_at").fetchall()
    with open("report_for_ic3.md", "w", encoding="utf-8") as f:
        f.write(f"# Binance hack (29 Oct 2026) - on-chain observations\n\nGenerated: {now()}\n\n")
        f.write("Starting point: the 628 addresses in the FBI alert of 31 October 2026.\n"
                "All data below is from public blockchains and can be verified via the links.\n\n")
        f.write(f"## Funds reaching freezable points ({len(high)})\n\n")
        for a in high:
            f.write(f"- **{a['amount']:,.4f} {a['asset']}** on {a['chain']} at {a['tx_time']}\n"
                    f"  - From: `{a['src']}`\n  - To: `{a['dst']}` ({a['reason']})\n"
                    f"  - Tx: {EXPL_TX[a['chain']].format(a['txid'])}\n")
        f.write(f"\n## Earlier flows into freezable points, found while mapping history ({len(past)})\n\n")
        for a in past:
            f.write(f"- {a['amount']:,.4f} {a['asset']} on {a['chain']} at {a['tx_time']}: "
                    f"`{a['src']}` → `{a['dst']}` ({a['reason']}) - {EXPL_TX[a['chain']].format(a['txid'])}\n")
        f.write(f"\n## Addresses discovered beyond the FBI list ({len(hops)})\n\n")
        for h in hops:
            f.write(f"- `{h['address']}` ({h['chain']}, hop {h['depth']}) received from `{h['parent']}` "
                    f"in tx {EXPL_TX[h['chain']].format(h['via_tx'])}"
                    f"{' - ' + h['label'] if h['label'] else ''}\n")
        f.write("\n---\nVerify each item before reporting. Report at https://www.ic3.gov "
                "with wallet addresses and transaction IDs.\n")
    print(f"Wrote alerts.csv ({len(alerts)}), edges.csv, nodes.csv, report_for_ic3.md "
          f"({len(high)} high-priority, {len(hops)} new addresses)")


def cmd_status(con):
    q = lambda s: con.execute(s).fetchone()[0]
    print(f"Watchlist: {q('SELECT COUNT(*) FROM addresses')} "
          f"(FBI {q('SELECT COUNT(*) FROM addresses WHERE depth=0')}, "
          f"discovered {q('SELECT COUNT(*) FROM addresses WHERE depth>0')})")
    print(f"Mapped money flows: {q('SELECT COUNT(*) FROM edges')}")
    n_high = q("SELECT COUNT(*) FROM alerts WHERE level='HIGH'")
    n_past = q("SELECT COUNT(*) FROM alerts WHERE level='PAST'")
    print(f"Alerts: {q('SELECT COUNT(*) FROM alerts')} (HIGH {n_high}, historical freeze points {n_past})")
    for r in con.execute("SELECT depth, COUNT(*) c FROM addresses GROUP BY depth"):
        print(f"  hop {r['depth']}: {r['c']} addresses")


def main():
    p = argparse.ArgumentParser(description="Follow-the-money tracer (read-only)")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init")
    sub.add_parser("scan")
    w = sub.add_parser("watch")
    w.add_argument("--every", type=float, default=10, help="minutes between passes")
    sub.add_parser("report")
    sub.add_parser("status")
    args = p.parse_args()

    con = db()
    if args.cmd == "init":
        cmd_init(con)
    elif args.cmd == "scan":
        Tracer(con, Sources()).scan()
    elif args.cmd == "watch":
        src = Sources()
        while True:
            t = Tracer(con, src)
            t.scan()
            if t.new_alerts:
                cmd_report(con)
            print(f"Sleeping {args.every} min… (Ctrl+C to stop)\n")
            time.sleep(args.every * 60)
    elif args.cmd == "report":
        cmd_report(con)
    elif args.cmd == "status":
        cmd_status(con)


if __name__ == "__main__":
    main()