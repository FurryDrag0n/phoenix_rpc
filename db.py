import sqlite3
import toml

with open("config.toml") as f:
    config = toml.load(f)

DB_PATH = config["database"]["path"]

def get_db_connection():
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=10000")
    return conn

def checkpoint_wal():
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    conn.close()

def init_db():
    conn = get_db_connection()
    c = conn.cursor()

    c.execute('''
        CREATE TABLE IF NOT EXISTS wallets (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            salt          BLOB NOT NULL,
            redeem_script BLOB NOT NULL,
            script_hash   BLOB NOT NULL,
            address       TEXT NOT NULL UNIQUE,
            account       TEXT DEFAULT '',
            created_at    INTEGER DEFAULT (strftime('%s', 'now'))
        )
    ''')
    c.execute('CREATE INDEX IF NOT EXISTS idx_wallets_address ON wallets(address)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_wallets_script_hash ON wallets(script_hash)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_wallets_account ON wallets(account)')

    c.execute('''
        CREATE TABLE IF NOT EXISTS utxos (
            txid          TEXT NOT NULL,
            vout          INTEGER NOT NULL,
            redeem_script BLOB NOT NULL,
            amount        INTEGER NOT NULL,
            block_height  INTEGER,
            spent         INTEGER DEFAULT 0,
            PRIMARY KEY (txid, vout)
        )
    ''')
    c.execute('CREATE INDEX IF NOT EXISTS idx_utxos_spent ON utxos(spent)')

    conn.commit()
    conn.close()
