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


def _column_exists(c, table: str, column: str) -> bool:
    c.execute(f"PRAGMA table_info({table})")
    return any(row[1] == column for row in c.fetchall())


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

    if not _column_exists(c, "wallets", "counter"):
        c.execute("ALTER TABLE wallets ADD COLUMN counter INTEGER")
        print("[DB] Migrated: added wallets.counter")

    c.execute('''
        CREATE UNIQUE INDEX IF NOT EXISTS idx_wallets_counter
        ON wallets(counter) WHERE counter IS NOT NULL
    ''')

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
    c.execute('CREATE INDEX IF NOT EXISTS idx_utxos_block_height ON utxos(block_height)')

    c.execute('''
        CREATE TABLE IF NOT EXISTS history (
            txid          TEXT PRIMARY KEY,
            category      TEXT NOT NULL,
            amount_net    INTEGER NOT NULL,
            fee           INTEGER DEFAULT 0,
            address       TEXT,
            account       TEXT DEFAULT '',
            block_height  INTEGER,
            block_time    INTEGER,
            n_time        INTEGER,
            comment       TEXT,
            created_at    INTEGER DEFAULT (strftime('%s', 'now'))
        )
    ''')
    c.execute('CREATE INDEX IF NOT EXISTS idx_history_category ON history(category)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_history_address ON history(address)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_history_block ON history(block_height)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_history_created ON history(created_at)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_history_n_time ON history(n_time)')

    c.execute('''
        CREATE TABLE IF NOT EXISTS priority_txs (
            txid         TEXT PRIMARY KEY,
            chain_id     TEXT NOT NULL,
            kind         TEXT NOT NULL,
            seq          INTEGER NOT NULL,
            raw          BLOB NOT NULL,
            prev_txid    TEXT,
            prev_vout    INTEGER,
            size         INTEGER NOT NULL,
            n_time       INTEGER,
            added_at     INTEGER DEFAULT (strftime('%s','now')),
            comment      TEXT
        )
    ''')
    c.execute('''
        CREATE INDEX IF NOT EXISTS idx_priority_chain
        ON priority_txs(chain_id, seq)
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS pstore_anchor (
            id            INTEGER PRIMARY KEY CHECK (id = 1),
            txid          TEXT,
            vout          INTEGER DEFAULT 0,
            redeem_script BLOB,
            address       TEXT,
            confirmed     INTEGER DEFAULT 0,
            updated_at    INTEGER DEFAULT (strftime('%s','now'))
        )
    ''')
    c.execute('INSERT OR IGNORE INTO pstore_anchor (id) VALUES (1)')

    conn.commit()
    conn.close()
