import os
import sys
import platform
import getpass

def _daemon_conf_path():
    system = platform.system()

    if system == "Windows":
        user = os.environ.get("USERNAME") or getpass.getuser()
        base = os.path.join(
            "C:\\Users", user, "AppData", "Roaming", "novacoin"
        )
        appdata = os.environ.get("APPDATA")
        if appdata:
            base = os.path.join(appdata, "novacoin")
        return os.path.join(base, "novacoin.conf")

    home = os.path.expanduser("~")
    return os.path.join(home, ".novacoin", "novacoin.conf")

def _parse_daemon_conf(path):
    result = {}
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#") or line.startswith(";"):
                continue
            if "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip().lower()
            value = value.strip()
            if " #" in value:
                value = value.split(" #", 1)[0].strip()
            if " ;" in value:
                value = value.split(" ;", 1)[0].strip()
            result[key] = value
    return result

def _detect_testnet(daemon_conf):
    val = daemon_conf.get("testnet", "").lower()
    return val in ("1", "true", "yes", "on")

def _detect_rpcport(daemon_conf, is_testnet):
    port = daemon_conf.get("rpcport")
    if port:
        try:
            return int(port)
        except ValueError:
            pass
    return 18344 if is_testnet else 8344

def _write_config_toml(rpcuser, rpcpassword, rpcport, is_testnet, path):
    content = f"""[daemon]
url = "http://127.0.0.1:{rpcport}"
user = "{rpcuser}"
password = "{rpcpassword}"

[proxy]
host = "127.0.0.1"
port = {16665 if is_testnet else 16666}

[wallet]
sat_per_byte = 1
dust_threshold = 1000

[database]
path = "wallets.db"

[network]
testnet = {"true" if is_testnet else "false"}
"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)

def generate_config(path="config.toml"):
    daemon_path = _daemon_conf_path()

    print(f"[CONF] config.toml not found, looking for daemon conf at:")
    print(f"[CONF]   {daemon_path}")

    if not os.path.isfile(daemon_path):
        print(f"[CONF] daemon conf not found")
        return False

    try:
        daemon_conf = _parse_daemon_conf(daemon_path)
    except Exception as e:
        print(f"[CONF] failed to parse daemon conf: {e}")
        return False

    rpcuser = daemon_conf.get("rpcuser")
    rpcpassword = daemon_conf.get("rpcpassword")

    if not rpcuser or not rpcpassword:
        print(f"[CONF] rpcuser/rpcpassword missing in daemon conf")
        return False

    is_testnet = _detect_testnet(daemon_conf)
    rpcport = _detect_rpcport(daemon_conf, is_testnet)

    _write_config_toml(rpcuser, rpcpassword, rpcport, is_testnet, path)

    print(f"[CONF] Generated {path}")
    print(f"[CONF]   daemon url: http://127.0.0.1:{rpcport}")
    print(f"[CONF]   rpc user:   {rpcuser}")
    print(f"[CONF]   testnet:    {is_testnet}")
    return True
