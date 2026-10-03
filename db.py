#!/usr/bin/env python3
"""
Схема БД Phoenix.
Единый источник правды по сети — config.toml [network].testnet.

Таблицы:
  wallets  — сгенерированные Falcon-адреса (соль + скрипты)
  utxos    — непотраченные выходы (чистый набор для траты)
  history  — вся история событий (signed amounts, тип операции)
"""

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

    # ---------- wallets ----------
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

    # ---------- utxos ----------
    # Чистый набор непотраченных выходов. Тип операции (mined/receive/send)
    # хранится в history, а не здесь.
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

    # ---------- history ----------
    # Вся история событий кошелька. category:
    #   receive       — входящий платёж
    #   send          — исходящий платёж (с внешним получателем)
    #   consolidate   — консолидация (все выходы наши)
    #   mined_pow     — PoW-награда (coinbase)
    #   mined_pos     — PoS-награда (coinstake)
    #
    # amount_net — знаковая нетто-сумма для кошелька:
    #   receive/mined_*  → положительная
    #   send/consolidate → отрицательная (учитывая fee)
    #   при нуле (net-0 блок) → 0
    #
    # fee — только для send/consolidate (0 иначе)
    # address — наш адрес для receive/mined_*, адрес получателя для send
    # block_height — NULL для неподтверждённых (мемпул)
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

    conn.commit()
    conn.close()
