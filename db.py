"""SQLite helper for VK Cloud VM parser."""
import sqlite3
import json
from pathlib import Path


def load_config_from_db(db_path: str) -> dict:
    """Load config and accounts from SQLite DB."""
    config = {}
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row

        # Config
        for row in conn.execute("SELECT key, value FROM config"):
            val = row['value']
            if val and (val[0] == '{' or val[0] == '['):
                try:
                    config[row['key']] = json.loads(val)
                except Exception:
                    config[row['key']] = val
            elif val and val.isdigit():
                config[row['key']] = int(val)
            else:
                config[row['key']] = val

        # Accounts
        accounts = []
        for row in conn.execute("SELECT * FROM accounts ORDER BY id"):
            acc = dict(row)
            acc['active'] = acc.get('active') == 1
            if acc.get('zones'):
                try:
                    acc['zones'] = json.loads(acc['zones'])
                except Exception:
                    pass
            accounts.append(acc)
        config['accounts'] = accounts

        conn.close()
    except Exception:
        pass
    return config


def save_found_vm(vm_info: dict, db_path: str) -> bool:
    """Save a found VM to the database."""
    try:
        conn = sqlite3.connect(db_path)
        conn.execute("""
            INSERT INTO found_vms (instance_id, ip, zone, username, account_name,
                account_folder_id, account_proxy, private_key_path, public_key_path,
                root_login, root_password, ssh_port, source_file)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            vm_info.get('instance_id'),
            vm_info.get('ip'),
            vm_info.get('zone'),
            vm_info.get('username'),
            vm_info.get('account_name'),
            vm_info.get('account_folder_id'),
            vm_info.get('account_proxy'),
            vm_info.get('private_key_path'),
            vm_info.get('public_key_path'),
            vm_info.get('root_login'),
            vm_info.get('root_password'),
            vm_info.get('ssh_port', 22),
            'parser'
        ))
        conn.commit()
        conn.close()
        return True
    except Exception:
        return False


def mark_telegram_sent(instance_id_or_ip: str, db_path: str):
    """Mark a found VM as telegram_sent."""
    try:
        conn = sqlite3.connect(db_path)
        conn.execute("UPDATE found_vms SET telegram_sent = 1 WHERE instance_id = ? OR ip = ?",
                      (instance_id_or_ip, instance_id_or_ip))
        conn.commit()
        conn.close()
    except Exception:
        pass
