#!/usr/bin/env python3
"""
VK Cloud VM Parser
Автоматическое создание VM в VK Cloud (OpenStack) и поиск IP-адресов с заданными подсетями.
Подход: floating IP-only hunting (создаём IP → проверяем CIDR → VM только для найденного).
"""
import sys
import io
if sys.platform == 'win32':
    try:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')
    except Exception:
        pass
try:
    sys.stdout.reconfigure(line_buffering=True)
    sys.stderr.reconfigure(line_buffering=True)
except Exception:
    pass

import time
import json
import os
import platform
import ipaddress
import threading
import random
from typing import List, Optional, Dict
from pathlib import Path
import re
from datetime import datetime
import subprocess
import secrets
import string

# TLS fingerprint Chrome -- curl_cffi with fallback to requests
_socks_proxy = os.environ.get('SOCKS5_PROXY', '').strip()
_proxy_dict = None
if _socks_proxy:
    _proxy_url = f'socks5h://{_socks_proxy}'
    _proxy_dict = {"http": _proxy_url, "https": _proxy_url}
    os.environ['ALL_PROXY'] = _proxy_url
    os.environ['HTTP_PROXY'] = _proxy_url
    os.environ['HTTPS_PROXY'] = _proxy_url
    print(f'[PROXY] SOCKS5 proxy: {_socks_proxy.split("@")[-1]}')

try:
    from curl_cffi import requests
    _USE_CURL_CFFI = True
    print('[TLS] curl_cffi -- fingerprint Chrome')
except ImportError:
    import requests
    _USE_CURL_CFFI = False
    print('[TLS] requests -- standard fingerprint')


def _req_get(url, **kwargs):
    if _USE_CURL_CFFI:
        kwargs.setdefault('impersonate', 'chrome131')
        if _proxy_dict:
            kwargs.setdefault('proxies', _proxy_dict)
    return requests.get(url, **kwargs)


def _req_post(url, **kwargs):
    if _USE_CURL_CFFI:
        kwargs.setdefault('impersonate', 'chrome131')
        if _proxy_dict:
            kwargs.setdefault('proxies', _proxy_dict)
    return requests.post(url, **kwargs)


def _req_put(url, **kwargs):
    if _USE_CURL_CFFI:
        kwargs.setdefault('impersonate', 'chrome131')
        if _proxy_dict:
            kwargs.setdefault('proxies', _proxy_dict)
    return requests.put(url, **kwargs)


def _req_delete(url, **kwargs):
    if _USE_CURL_CFFI:
        kwargs.setdefault('impersonate', 'chrome131')
        if _proxy_dict:
            kwargs.setdefault('proxies', _proxy_dict)
    return requests.delete(url, **kwargs)

try:
    import paramiko
except ImportError:
    paramiko = None

try:
    import socks as _socks_module
except ImportError:
    _socks_module = None


def _make_proxy_sock(host: str, port: int):
    """Creates a SOCKS5 socket for SSH connections via account proxy."""
    proxy_str = os.environ.get('SOCKS5_PROXY', '').strip()
    if not proxy_str or not _socks_module:
        return None
    try:
        auth_part, addr_part = proxy_str.rsplit('@', 1) if '@' in proxy_str else ('', proxy_str)
        proxy_host, proxy_port = addr_part.split(':')
        proxy_user = proxy_pass = None
        if auth_part and ':' in auth_part:
            proxy_user, proxy_pass = auth_part.split(':', 1)
        sock = _socks_module.create_connection(
            (host, port),
            proxy_type=_socks_module.SOCKS5,
            proxy_addr=proxy_host,
            proxy_port=int(proxy_port),
            proxy_username=proxy_user,
            proxy_password=proxy_pass,
            timeout=15,
        )
        return sock
    except Exception as e:
        print(f"  [PROXY-SSH] Failed to create SOCKS socket: {e}")
        return None


# ═══════════════════════════════════════════════════════════════════════════════
# Профили поиска (как в NewHunter)
# ═══════════════════════════════════════════════════════════════════════════════

PROFILES = {
    "fast": {
        "name": "Быстрый",
        "description": "Минимальные задержки, максимальная скорость (риск блокировки выше)",
        "base_delay_min": 2,
        "base_delay_max": 5,
        "attempts_per_session": 10,
        "session_pause_min": 60,
        "session_pause_max": 120,
        "keep_bad_ip_min": 0,
        "keep_bad_ip_max": 5,
        "max_total_attempts": 1500,
        "reset_sleep_minutes": 10,
    },
    "balanced": {
        "name": "Сбалансированный",
        "description": "Баланс между скоростью и безопасностью (рекомендуется)",
        "base_delay_min": 5,
        "base_delay_max": 10,
        "attempts_per_session": 20,
        "session_pause_min": 60,
        "session_pause_max": 250,
        "keep_bad_ip_min": 5,
        "keep_bad_ip_max": 60,
        "max_total_attempts": 2000,
        "reset_sleep_minutes": 20,
    },
    "safe": {
        "name": "Безопасный",
        "description": "Максимальные задержки, минимальный риск блокировки",
        "base_delay_min": 15,
        "base_delay_max": 30,
        "attempts_per_session": 4,
        "session_pause_min": 300,
        "session_pause_max": 600,
        "keep_bad_ip_min": 60,
        "keep_bad_ip_max": 120,
        "max_total_attempts": 3000,
        "reset_sleep_minutes": 30,
    },
    "no_pause": {
        "name": "Без пауз",
        "description": "Быстрый режим без больших пауз между сессиями",
        "base_delay_min": 3,
        "base_delay_max": 7,
        "attempts_per_session": 20,
        "session_pause_min": 10,
        "session_pause_max": 30,
        "keep_bad_ip_min": 0,
        "keep_bad_ip_max": 3,
        "max_total_attempts": 1000,
        "reset_sleep_minutes": 5,
    },
    "test": {
        "name": "Тестовый",
        "description": "Быстрый тест с 6 попытками (2 в сессии, сон 2 мин)",
        "base_delay_min": 2,
        "base_delay_max": 5,
        "attempts_per_session": 2,
        "session_pause_min": 10,
        "session_pause_max": 20,
        "keep_bad_ip_min": 0,
        "keep_bad_ip_max": 3,
        "max_total_attempts": 6,
        "reset_sleep_minutes": 2,
    },
}


def get_profile(key: str) -> dict:
    """Получить профиль по ключу."""
    return PROFILES.get(key, PROFILES["balanced"])


# ═══════════════════════════════════════════════════════════════════════════════
# CIDR / подсеть matching
# ═══════════════════════════════════════════════════════════════════════════════

def is_target_ip(ip_str: str, cidrs: list) -> bool:
    """
    Проверить, попадает ли IP в одну из целевых подсетей.
    Поддерживает CIDR (95.163.248.0/22) и префиксы (95.163).
    """
    if not ip_str:
        return False
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    for cidr in cidrs:
        cidr = cidr.strip()
        if not cidr:
            continue
        if '/' in cidr:
            try:
                if ip in ipaddress.ip_network(cidr, strict=False):
                    return True
            except ValueError:
                pass
        else:
            # Legacy prefix matching (e.g. "95.163")
            if ip_str.startswith(cidr):
                return True
    return False


def parse_cidrs(cidr_string: str) -> list:
    """Разбирает строку подсетей (через запятую) в список."""
    return [c.strip() for c in cidr_string.split(',') if c.strip()]


# ═══════════════════════════════════════════════════════════════════════════════
# Фоновое удаление floating IP с задержкой
# ═══════════════════════════════════════════════════════════════════════════════

class IPDeleter:
    """Управление фоновым удалением ненужных IP с задержкой."""

    def __init__(self, delete_fn, keep_min: int = 0, keep_max: int = 5, max_retries: int = 3):
        self.delete_fn = delete_fn
        self.keep_min = keep_min
        self.keep_max = keep_max
        self.max_retries = max_retries
        self._threads = []

    def schedule(self, fip_id: str, ip_addr: str):
        """Запускает отложенное удаление IP в отдельном потоке."""
        t = threading.Thread(target=self._do_delete, args=(fip_id, ip_addr), daemon=True)
        self._threads.append(t)
        t.start()

    def _do_delete(self, fip_id: str, ip_addr: str):
        wait = random.randint(self.keep_min, self.keep_max)
        if wait > 0:
            time.sleep(wait)
        for attempt in range(1, self.max_retries + 1):
            try:
                if self.delete_fn(fip_id, silent=True):
                    return
            except Exception:
                pass
            if attempt < self.max_retries:
                time.sleep(2 ** attempt)

    def wait_all(self, timeout: int = 120):
        """Дождаться завершения всех потоков удаления."""
        for t in self._threads:
            if t.is_alive():
                t.join(timeout=timeout)
        self._threads.clear()

    @property
    def active_count(self) -> int:
        return sum(1 for t in self._threads if t.is_alive())


class VKCloudVM:
    """VK Cloud (OpenStack) VM management client."""

    KEYSTONE_URL = "https://infra.mail.ru:35357/v3/auth/tokens"
    COMPUTE_URL = "https://infra.mail.ru:8774/v2.1"
    NEUTRON_URL = "https://infra.mail.ru:9696"
    GLANCE_URL = "https://infra.mail.ru:9292"

    def __init__(self, username: str, password: str, project_id: str,
                 zone: str = "MS1", enable_logging: bool = True):
        self.username = username
        self.password = password
        self.project_id = project_id
        self.zone = zone
        self.token = None
        self.token_expires_at = 0
        self.created_instances = []
        self.created_volumes = []
        self.created_floating_ips = []
        self.enable_logging = True
        self.log_file = None

        if self.enable_logging:
            log_dir = Path(__file__).parent / "logs"
            log_dir.mkdir(exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            self.log_file = log_dir / f"ip_check_{timestamp}.log"
            self._log(f"=== Session started ===")
            self._log(f"Zone: {zone}, Project: {project_id}, User: {username}")

        # Authenticate immediately
        self._authenticate()

    def _log(self, message: str, level: str = "INFO"):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        log_message = f"[{timestamp}] [{level}] {message}"
        if self.enable_logging and self.log_file:
            try:
                with open(self.log_file, 'a', encoding='utf-8') as f:
                    f.write(log_message + '\n')
            except Exception:
                pass
        if level in ["ERROR", "WARNING", "INFO"]:
            print(log_message)

    def _cinder_url(self):
        return f"https://public.infra.mail.ru:8776/v3/{self.project_id}"

    def _authenticate(self):
        """Authenticate via Keystone v3 and get X-Subject-Token."""
        payload = {
            "auth": {
                "identity": {
                    "methods": ["password"],
                    "password": {
                        "user": {
                            "domain": {"name": "users"},
                            "name": self.username,
                            "password": self.password
                        }
                    }
                },
                "scope": {
                    "project": {
                        "id": self.project_id,
                        "region": "RegionOne"
                    }
                }
            }
        }

        for attempt in range(3):
            try:
                self._log(f"Keystone auth attempt {attempt + 1}/3...", "INFO")
                response = _req_post(
                    self.KEYSTONE_URL,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                    timeout=20
                )

                if response.status_code in (200, 201):
                    self.token = response.headers.get("X-Subject-Token")
                    if self.token:
                        self.token_expires_at = time.time() + 3600 * 10
                        self._log(f"Keystone auth OK, token: {self.token[:20]}...", "INFO")
                        return
                    else:
                        self._log("Keystone auth: no X-Subject-Token in response", "ERROR")
                else:
                    body = response.text[:300] if hasattr(response, 'text') else 'N/A'
                    self._log(f"Keystone auth HTTP {response.status_code}: {body}", "ERROR")

            except Exception as e:
                self._log(f"Keystone auth error: {e}", "ERROR")

            if attempt < 2:
                wait = 5 * (attempt + 1)
                self._log(f"Retrying in {wait}s...", "WARNING")
                time.sleep(wait)

        raise Exception("Failed to authenticate with Keystone after 3 attempts")

    def _ensure_token(self):
        """Re-authenticate if token is expired or missing."""
        if not self.token or time.time() > self.token_expires_at:
            self._log("Token expired or missing, re-authenticating...", "INFO")
            self._authenticate()

    def _auth_headers(self):
        """Return headers with auth token."""
        self._ensure_token()
        return {
            "X-Auth-Token": self.token,
            "Content-Type": "application/json",
        }

    def _request_with_reauth(self, method, url, **kwargs):
        """Make a request with automatic re-authentication on 401."""
        kwargs.setdefault('timeout', 30)
        headers = kwargs.pop('headers', {})
        headers.update(self._auth_headers())
        kwargs['headers'] = headers

        req_func = {
            'GET': _req_get, 'POST': _req_post,
            'PUT': _req_put, 'DELETE': _req_delete
        }[method.upper()]

        response = req_func(url, **kwargs)

        if response.status_code == 401:
            self._log("Got 401, re-authenticating...", "WARNING")
            self._authenticate()
            kwargs['headers'].update(self._auth_headers())
            response = req_func(url, **kwargs)

        return response

    # ---- External Network Discovery ----

    def find_external_network(self) -> Optional[str]:
        """Find external network ID (ext-net) for floating IPs."""
        url = f"{self.NEUTRON_URL}/v2.0/networks"
        try:
            response = self._request_with_reauth('GET', url, params={"router:external": "True"})
            if response.status_code == 200:
                networks = response.json().get("networks", [])
                for net in networks:
                    if net.get("router:external"):
                        net_id = net.get("id")
                        net_name = net.get("name", "unknown")
                        self._log(f"Found external network: {net_name} ({net_id})", "INFO")
                        return net_id
                self._log("No external network found", "WARNING")
            else:
                self._log(f"List networks: HTTP {response.status_code}", "ERROR")
        except Exception as e:
            self._log(f"Error finding external network: {e}", "ERROR")
        return None

    # ---- Volume Management ----

    def create_bootable_volume(self, image_id: str, size: int = 10,
                                volume_type: str = "ceph-ssd") -> Optional[str]:
        """Create a bootable volume from image."""
        url = f"{self._cinder_url()}/volumes"
        vol_name = f"boot-vol-{secrets.token_hex(4)}"
        payload = {
            "volume": {
                "size": size,
                "name": vol_name,
                "imageRef": image_id,
                "volume_type": volume_type,
                "availability_zone": self.zone
            }
        }

        try:
            self._log(f"Creating bootable volume '{vol_name}' from image {image_id}...", "INFO")
            response = self._request_with_reauth('POST', url, json=payload)

            if response.status_code in (200, 202):
                volume = response.json().get("volume", {})
                volume_id = volume.get("id")
                if volume_id:
                    self.created_volumes.append(volume_id)
                    self._log(f"Volume created: {volume_id}", "INFO")
                    return volume_id
                else:
                    self._log("Volume created but no ID in response", "ERROR")
            else:
                body = response.text[:300] if hasattr(response, 'text') else 'N/A'
                self._log(f"Create volume HTTP {response.status_code}: {body}", "ERROR")
        except Exception as e:
            self._log(f"Error creating volume: {e}", "ERROR")
        return None

    def wait_for_volume_available(self, volume_id: str, timeout: int = 300) -> bool:
        """Wait for volume to become 'available'."""
        url = f"{self._cinder_url()}/volumes/{volume_id}"
        start = time.time()
        while time.time() - start < timeout:
            try:
                response = self._request_with_reauth('GET', url)
                if response.status_code == 200:
                    status = response.json().get("volume", {}).get("status", "")
                    if status == "available":
                        self._log(f"Volume {volume_id} is available", "INFO")
                        return True
                    elif status == "error":
                        self._log(f"Volume {volume_id} is in error state", "ERROR")
                        return False
                    else:
                        elapsed = int(time.time() - start)
                        if elapsed % 10 == 0:
                            self._log(f"Volume {volume_id} status: {status} ({elapsed}s)", "INFO")
            except Exception as e:
                self._log(f"Error checking volume status: {e}", "WARNING")
            time.sleep(3)

        self._log(f"Volume {volume_id} timeout after {timeout}s", "ERROR")
        return False

    def delete_volume(self, volume_id: str, silent: bool = False) -> bool:
        """Delete a volume."""
        url = f"{self._cinder_url()}/volumes/{volume_id}"
        for attempt in range(3):
            try:
                response = self._request_with_reauth('DELETE', url)
                if response.status_code in (200, 202, 204):
                    if not silent:
                        print(f"  Volume {volume_id[:12]}... deleted")
                    return True
                elif response.status_code == 404:
                    return True
                elif response.status_code == 409:
                    self._log(f"Volume {volume_id} conflict (409), retrying...", "WARNING")
                    time.sleep(5 * (attempt + 1))
                    continue
                else:
                    body = response.text[:200] if hasattr(response, 'text') else 'N/A'
                    self._log(f"Delete volume HTTP {response.status_code}: {body}", "WARNING")
            except Exception as e:
                self._log(f"Error deleting volume: {e}", "WARNING")
            time.sleep(3)
        return False

    # ---- Server (VM) Management ----

    def create_server(self, name: str, flavor_id: str, volume_id: str,
                      network_id: str, key_name: str = None,
                      user_data: str = None) -> Optional[str]:
        """Create a server (boot from volume)."""
        url = f"{self.COMPUTE_URL}/servers"

        server_spec = {
            "name": name,
            "flavorRef": flavor_id,
            "availability_zone": self.zone,
            "networks": [{"uuid": network_id}],
            "block_device_mapping_v2": [{
                "boot_index": 0,
                "uuid": volume_id,
                "source_type": "volume",
                "destination_type": "volume",
                "delete_on_termination": True
            }]
        }

        if key_name:
            server_spec["key_name"] = key_name
        if user_data:
            import base64
            server_spec["user_data"] = base64.b64encode(user_data.encode()).decode()

        try:
            self._log(f"Creating server '{name}'...", "INFO")
            response = self._request_with_reauth('POST', url, json={"server": server_spec})

            if response.status_code in (200, 202):
                server = response.json().get("server", {})
                server_id = server.get("id")
                if server_id:
                    self.created_instances.append(server_id)
                    self._log(f"Server created: {name} (ID: {server_id})", "INFO")
                    print(f"  Server created: {name} ({server_id[:12]}...)")
                    return server_id
                else:
                    self._log("Server created but no ID", "ERROR")
            else:
                body = response.text[:300] if hasattr(response, 'text') else 'N/A'
                self._log(f"Create server HTTP {response.status_code}: {body}", "ERROR")

                if response.status_code == 429:
                    self._log("Rate limited, waiting 30s...", "WARNING")
                    time.sleep(30)
                elif response.status_code in (403, 413):
                    self._log("Quota exceeded", "ERROR")
                    print(f"  Quota exceeded for server {name}")
        except Exception as e:
            self._log(f"Error creating server: {e}", "ERROR")
        return None

    def wait_for_server_active(self, server_id: str, timeout: int = 300) -> bool:
        """Wait for server to become ACTIVE."""
        url = f"{self.COMPUTE_URL}/servers/{server_id}"
        start = time.time()
        time.sleep(5)

        while time.time() - start < timeout:
            try:
                response = self._request_with_reauth('GET', url)
                if response.status_code == 200:
                    status = response.json().get("server", {}).get("status", "")
                    if status == "ACTIVE":
                        self._log(f"Server {server_id} is ACTIVE", "INFO")
                        return True
                    elif status == "ERROR":
                        self._log(f"Server {server_id} is in ERROR state", "ERROR")
                        return False
                    elif status in ("BUILD", "REBUILD"):
                        elapsed = int(time.time() - start)
                        if elapsed % 15 == 0:
                            print(f"    Server {server_id[:12]}... building ({elapsed}s)")
                    else:
                        self._log(f"Server {server_id} status: {status}", "INFO")
                elif response.status_code == 404:
                    self._log(f"Server {server_id} not found (404)", "WARNING")
            except Exception as e:
                self._log(f"Error checking server status: {e}", "WARNING")
            time.sleep(5)

        self._log(f"Server {server_id} timeout waiting for ACTIVE ({timeout}s)", "ERROR")
        return False

    def delete_server(self, server_id: str, silent: bool = False) -> bool:
        """Delete a server."""
        url = f"{self.COMPUTE_URL}/servers/{server_id}"
        for attempt in range(4):
            try:
                response = self._request_with_reauth('DELETE', url)
                if response.status_code in (200, 202, 204):
                    if not silent:
                        print(f"  Server {server_id[:12]}... deleted")
                    return True
                elif response.status_code == 404:
                    return True
                elif response.status_code == 409:
                    self._log(f"Server {server_id} conflict, retrying...", "WARNING")
                    time.sleep(5 * (attempt + 1))
                    continue
                elif response.status_code == 429:
                    wait = 5 * (attempt + 1)
                    self._log(f"Rate limited, retry in {wait}s", "WARNING")
                    time.sleep(wait)
                    continue
                else:
                    body = response.text[:200] if hasattr(response, 'text') else 'N/A'
                    if not silent:
                        self._log(f"Delete server HTTP {response.status_code}: {body}", "WARNING")
            except Exception:
                pass
            time.sleep(3)
        return False

    def force_delete_server(self, server_id: str) -> bool:
        """Force delete a server stuck in BUILD or ERROR."""
        url = f"{self.COMPUTE_URL}/servers/{server_id}/action"
        try:
            response = self._request_with_reauth('POST', url, json={"forceDelete": None})
            if response.status_code in (200, 202, 204):
                self._log(f"Force delete server {server_id}", "INFO")
                return True
        except Exception as e:
            self._log(f"Force delete error: {e}", "WARNING")
        return self.delete_server(server_id)

    # ---- Floating IP Management ----

    def create_floating_ip(self, ext_net_id: str) -> Optional[Dict]:
        """Allocate a floating IP."""
        url = f"{self.NEUTRON_URL}/v2.0/floatingips"
        payload = {
            "floatingip": {
                "floating_network_id": ext_net_id
            }
        }
        try:
            response = self._request_with_reauth('POST', url, json=payload)
            if response.status_code in (200, 201):
                fip = response.json().get("floatingip", {})
                fip_id = fip.get("id")
                fip_addr = fip.get("floating_ip_address")
                if fip_id:
                    self.created_floating_ips.append(fip_id)
                    self._log(f"Floating IP allocated: {fip_addr} ({fip_id})", "INFO")
                    return fip
            else:
                body = response.text[:300] if hasattr(response, 'text') else 'N/A'
                self._log(f"Create floating IP HTTP {response.status_code}: {body}", "ERROR")
        except Exception as e:
            self._log(f"Error creating floating IP: {e}", "ERROR")
        return None

    def get_server_port(self, server_id: str) -> Optional[str]:
        """Get the port ID for a server."""
        url = f"{self.NEUTRON_URL}/v2.0/ports"
        try:
            response = self._request_with_reauth('GET', url, params={"device_id": server_id})
            if response.status_code == 200:
                ports = response.json().get("ports", [])
                if ports:
                    port_id = ports[0].get("id")
                    self._log(f"Server {server_id} port: {port_id}", "INFO")
                    return port_id
                else:
                    self._log(f"No ports found for server {server_id}", "WARNING")
            else:
                self._log(f"Get ports HTTP {response.status_code}", "WARNING")
        except Exception as e:
            self._log(f"Error getting server port: {e}", "ERROR")
        return None

    def associate_floating_ip(self, fip_id: str, port_id: str) -> bool:
        """Associate a floating IP with a port."""
        url = f"{self.NEUTRON_URL}/v2.0/floatingips/{fip_id}"
        payload = {
            "floatingip": {
                "port_id": port_id
            }
        }
        try:
            response = self._request_with_reauth('PUT', url, json=payload)
            if response.status_code == 200:
                self._log(f"Floating IP {fip_id} associated with port {port_id}", "INFO")
                return True
            else:
                body = response.text[:300] if hasattr(response, 'text') else 'N/A'
                self._log(f"Associate floating IP HTTP {response.status_code}: {body}", "ERROR")
        except Exception as e:
            self._log(f"Error associating floating IP: {e}", "ERROR")
        return False

    def delete_floating_ip(self, fip_id: str, silent: bool = False) -> bool:
        """Delete a floating IP."""
        url = f"{self.NEUTRON_URL}/v2.0/floatingips/{fip_id}"
        try:
            response = self._request_with_reauth('DELETE', url)
            if response.status_code in (200, 204):
                if not silent:
                    self._log(f"Floating IP {fip_id} deleted", "INFO")
                return True
            elif response.status_code == 404:
                return True
        except Exception:
            pass
        return False

    def list_floating_ips(self) -> List[Dict]:
        """List all floating IPs in the project."""
        url = f"{self.NEUTRON_URL}/v2.0/floatingips"
        try:
            response = self._request_with_reauth('GET', url,
                                                  params={"project_id": self.project_id})
            if response.status_code == 200:
                return response.json().get("floatingips", [])
        except Exception:
            pass
        return []

    # ---- Listing and Cleanup ----

    def list_servers(self, silent: bool = False) -> List[Dict]:
        """List all servers in the project."""
        url = f"{self.COMPUTE_URL}/servers/detail"
        try:
            response = self._request_with_reauth('GET', url)
            if response.status_code == 200:
                servers = response.json().get("servers", [])
                if not silent:
                    print(f"Found {len(servers)} servers")
                return servers
        except Exception as e:
            if not silent:
                self._log(f"Error listing servers: {e}", "ERROR")
        return []

    def get_server_ip(self, server: Dict) -> Optional[str]:
        """Extract floating IP from server data."""
        addresses = server.get("addresses", {})
        for net_name, addr_list in addresses.items():
            for addr in addr_list:
                if addr.get("OS-EXT-IPS:type") == "floating":
                    return addr.get("addr")
        return None

    def check_ip_prefix(self, ip: str, prefix: str = "95.163") -> bool:
        """Check if IP starts with one of the given prefixes (comma-separated)."""
        if not ip:
            return False
        prefixes = [p.strip() for p in prefix.split(',') if p.strip()]
        return any(ip.startswith(p) for p in prefixes)

    def cleanup_vm(self, server_id: str, volume_id: str = None,
                   fip_id: str = None, silent: bool = False):
        """Full cleanup: delete server + floating IP + volume."""
        if fip_id:
            self.delete_floating_ip(fip_id, silent=True)
            if fip_id in self.created_floating_ips:
                self.created_floating_ips.remove(fip_id)
        if server_id:
            self.delete_server(server_id, silent=silent)
            if server_id in self.created_instances:
                self.created_instances.remove(server_id)
        if volume_id:
            time.sleep(5)
            self.delete_volume(volume_id, silent=True)
            if volume_id in self.created_volumes:
                self.created_volumes.remove(volume_id)

    def cleanup_all(self):
        """Cleanup all created resources."""
        if not self.created_instances and not self.created_floating_ips and not self.created_volumes:
            return
        print(f"\nCleanup: {len(self.created_instances)} servers, "
              f"{len(self.created_floating_ips)} floating IPs, "
              f"{len(self.created_volumes)} volumes...")

        for fip_id in list(self.created_floating_ips):
            try:
                self.delete_floating_ip(fip_id, silent=True)
            except Exception:
                pass
        self.created_floating_ips.clear()

        for server_id in list(self.created_instances):
            try:
                self.delete_server(server_id, silent=True)
            except KeyboardInterrupt:
                raise
            except Exception:
                pass
        self.created_instances.clear()

        time.sleep(5)
        for vol_id in list(self.created_volumes):
            try:
                self.delete_volume(vol_id, silent=True)
            except Exception:
                pass
        self.created_volumes.clear()

    def cleanup_all_project_servers(self, exclude_ids: List[str] = None) -> int:
        """Delete all servers in the project (except excluded)."""
        exclude_ids = exclude_ids or []
        servers = self.list_servers(silent=True)
        if not servers:
            return 0

        to_delete = [s for s in servers if s.get("id") not in exclude_ids]
        if not to_delete:
            return 0

        print(f"Deleting {len(to_delete)} servers...")
        deleted = 0
        for srv in to_delete:
            sid = srv.get("id")
            if self.delete_server(sid, silent=True):
                deleted += 1
            time.sleep(3 + secrets.randbelow(3))

        # Also clean up orphaned floating IPs
        fips = self.list_floating_ips()
        for fip in fips:
            if not fip.get("port_id"):
                self.delete_floating_ip(fip["id"], silent=True)

        if deleted > 0:
            print(f"  Deleted {deleted} servers")
            time.sleep(5)
        return deleted

    # ═══════════════════════════════════════════════════════════════════════════
    # VM creation for a found IP (volume → server → associate existing FIP)
    # ═══════════════════════════════════════════════════════════════════════════

    def create_vm_for_found_ip(self, fip_id: str, fip_addr: str,
                                image_id: str, flavor_id: str, network_id: str,
                                ssh_public_key: str = None) -> Optional[Dict]:
        """
        Создать VM и привязать к ней уже существующий floating IP.
        1. Create bootable volume
        2. Wait for volume
        3. Create server
        4. Wait for ACTIVE
        5. Associate floating IP with server port
        """
        vm_name = f"srv-{secrets.token_hex(4)}"

        # 1. Volume
        volume_id = self.create_bootable_volume(image_id)
        if not volume_id:
            return None

        # 2. Wait
        if not self.wait_for_volume_available(volume_id, timeout=180):
            self._log(f"Volume {volume_id} never became available", "ERROR")
            self.delete_volume(volume_id, silent=True)
            return None

        # 3. Server
        user_data = None
        if ssh_public_key:
            user_data = f"""#cloud-config
ssh_pwauth: no
users:
  - name: root
    ssh_authorized_keys:
      - {ssh_public_key}
"""

        server_id = self.create_server(vm_name, flavor_id, volume_id, network_id,
                                        user_data=user_data)
        if not server_id:
            self._log(f"Server creation failed, cleanup volume", "ERROR")
            self.delete_volume(volume_id, silent=True)
            return None

        # 4. Wait ACTIVE
        if not self.wait_for_server_active(server_id, timeout=300):
            self._log(f"Server {server_id} never became ACTIVE", "ERROR")
            self.force_delete_server(server_id)
            time.sleep(5)
            self.delete_volume(volume_id, silent=True)
            return None

        # 5. Associate floating IP
        port_id = None
        for attempt in range(5):
            port_id = self.get_server_port(server_id)
            if port_id:
                break
            time.sleep(3)

        if not port_id:
            self._log(f"No port found for server {server_id}", "ERROR")
            self.delete_server(server_id, silent=True)
            time.sleep(5)
            self.delete_volume(volume_id, silent=True)
            return None

        if not self.associate_floating_ip(fip_id, port_id):
            self._log(f"Failed to associate floating IP {fip_addr}", "ERROR")
            self.delete_server(server_id, silent=True)
            time.sleep(5)
            self.delete_volume(volume_id, silent=True)
            return None

        return {
            "server_id": server_id,
            "volume_id": volume_id,
            "fip_id": fip_id,
            "ip": fip_addr,
            "name": vm_name,
        }

    # ═══════════════════════════════════════════════════════════════════════════
    # Основной цикл поиска (floating IP-only hunting)
    # ═══════════════════════════════════════════════════════════════════════════

    def hunt_target_ip(self, image_id: str, flavor_id: str, network_id: str,
                       target_cidrs: list, profile_key: str = "balanced",
                       zones: list = None, telegram_config: Dict = None,
                       ssh_info: Dict = None, account_info: Dict = None) -> Optional[Dict]:
        """
        Основной цикл поиска IP с профилями, сессиями, лимитами.
        Подход: создаём floating IP → проверяем CIDR → если нашёл, создаём VM.
        """
        profile = get_profile(profile_key)
        ext_net_id = self.find_external_network()
        if not ext_net_id:
            print("  ERROR: Cannot find external network for floating IPs")
            return None

        # SSH key
        ssh_public_key = None
        if ssh_info and ssh_info.get("public_key_path"):
            try:
                with open(ssh_info["public_key_path"], 'r') as f:
                    ssh_public_key = f.read().strip()
            except Exception as e:
                self._log(f"Error reading SSH public key: {e}", "WARNING")

        if zones is None:
            zones = [self.zone]

        # Check existing floating IPs for target
        existing_fips = self.list_floating_ips()
        for fip in existing_fips:
            fip_addr = fip.get("floating_ip_address")
            if fip_addr and is_target_ip(fip_addr, target_cidrs):
                self._log(f"Found existing floating IP {fip_addr} matching target!", "INFO")
                print(f"\n{'='*60}")
                print(f"  Found existing IP matching target!")
                print(f"  IP: {fip_addr}")
                print(f"{'='*60}\n")

        # Clean up orphaned floating IPs (not associated with any port)
        orphaned = [f for f in existing_fips
                    if not f.get("port_id") and not is_target_ip(f.get("floating_ip_address", ""), target_cidrs)]
        if orphaned:
            print(f"  Cleaning up {len(orphaned)} orphaned floating IPs...")
            for fip in orphaned:
                self.delete_floating_ip(fip["id"], silent=True)

        # IP Deleter for background cleanup
        ip_deleter = IPDeleter(
            self.delete_floating_ip,
            keep_min=profile["keep_bad_ip_min"],
            keep_max=profile["keep_bad_ip_max"],
        )

        # Stats
        total_attempts = 0
        found_ips = 0
        zone_index = 0

        cidrs_display = ", ".join(target_cidrs)
        print(f"\n{'='*60}")
        print(f"  Профиль: {profile['name']}")
        print(f"  Лимит попыток: {profile['max_total_attempts']}")
        print(f"  Время сна: {profile['reset_sleep_minutes']} мин")
        print(f"  Целевые подсети: {cidrs_display}")
        print(f"  Зоны: {', '.join(zones)}")
        print(f"{'='*60}\n")

        try:
            while True:
                # ─── Reset cycle ───
                session_num = 0
                total_attempts = 0

                while total_attempts < profile["max_total_attempts"]:
                    session_num += 1
                    session_attempts = 0
                    current_zone = zones[zone_index % len(zones)]
                    self.zone = current_zone

                    print(f"\n{'─'*50}")
                    print(f"  Сессия #{session_num} | Зона: {current_zone}")
                    print(f"  Попытки: {total_attempts}/{profile['max_total_attempts']}")
                    print(f"{'─'*50}")

                    while session_attempts < profile["attempts_per_session"]:
                        if total_attempts >= profile["max_total_attempts"]:
                            break

                        total_attempts += 1
                        session_attempts += 1

                        # Create floating IP
                        fip_data = self.create_floating_ip(ext_net_id)
                        if not fip_data:
                            self._log("Failed to create floating IP (quota?)", "ERROR")
                            # Wait before retry
                            wait_sec = random.randint(30, 60)
                            print(f"  Ожидание {wait_sec}с (квота?)...")
                            time.sleep(wait_sec)
                            continue

                        fip_id = fip_data["id"]
                        fip_addr = fip_data["floating_ip_address"]

                        print(f"  [{total_attempts}/{profile['max_total_attempts']}] IP: {fip_addr}", end="")

                        # Check CIDR match
                        if is_target_ip(fip_addr, target_cidrs):
                            found_ips += 1
                            print(f" -- НАЙДЕН!")
                            self._log(f"FOUND TARGET IP! {fip_addr} (attempt {total_attempts})", "INFO")

                            print(f"\n{'='*60}")
                            print(f"  НАЙДЕН IP В ЦЕЛЕВОЙ ПОДСЕТИ!")
                            print(f"  IP: {fip_addr}")
                            print(f"  Попытка: {total_attempts}/{profile['max_total_attempts']}")
                            print(f"  Зона: {current_zone}")
                            print(f"{'='*60}")

                            # Create VM for this IP
                            print(f"\n  Создание VM для IP {fip_addr}...")
                            vm_info = self.create_vm_for_found_ip(
                                fip_id, fip_addr, image_id, flavor_id, network_id,
                                ssh_public_key=ssh_public_key
                            )

                            if vm_info:
                                _ai = account_info or {}
                                vm_info['zone'] = current_zone
                                vm_info['account_name'] = _ai.get('account_name', '')
                                vm_info['account_folder_id'] = _ai.get('account_folder_id', _ai.get('project_id', ''))
                                vm_info['account_proxy'] = _ai.get('account_proxy', '')
                                vm_info['account_id'] = _ai.get('account_id', '')

                                if ssh_info:
                                    vm_info['username'] = ssh_info.get('username', 'root')
                                    vm_info['private_key_path'] = ssh_info.get('private_key_path')
                                    vm_info['public_key_path'] = ssh_info.get('public_key_path')
                                else:
                                    vm_info['username'] = 'root'

                                # SSH setup
                                try:
                                    if vm_info.get('private_key_path') and vm_info.get('username'):
                                        print("Waiting for SSH (up to 2 min)...")
                                        if wait_for_ssh(vm_info['ip'], vm_info['username'],
                                                        vm_info['private_key_path'], port=22, timeout=120):
                                            print("Connected, setting up password login...")
                                            root_pass = ensure_root_password_login_works(
                                                vm_info['ip'], vm_info['username'],
                                                vm_info['private_key_path'], port=22
                                            )
                                            if root_pass:
                                                vm_info['root_login'] = 'root'
                                                vm_info['root_password'] = root_pass
                                                vm_info['ssh_port'] = 22
                                            else:
                                                print("  Password login not configured")
                                        else:
                                            print("  SSH not available within 2 min")
                                except Exception as _ssh_e:
                                    print(f"  SSH setup error: {_ssh_e}")

                                try:
                                    send_notification(vm_info, telegram_config)
                                except Exception as _notif_e:
                                    print(f"  Notification error: {_notif_e}")

                                # Log found server
                                try:
                                    _log_path = Path(__file__).parent / "found_servers.log"
                                    _ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                    _lines = [
                                        f"{'='*60}",
                                        f"[{_ts}] SERVER FOUND",
                                        f"  Account : {vm_info.get('account_name', '?')}",
                                        f"  Project : {vm_info.get('account_folder_id', '?')}",
                                        f"  Proxy   : {vm_info.get('account_proxy', '--')}",
                                        f"  VM ID   : {vm_info.get('instance_id', '?')}",
                                        f"  IP      : {vm_info.get('ip', '?')}",
                                        f"  Zone    : {vm_info.get('zone', '?')}",
                                        f"  Login   : {vm_info.get('root_login') or vm_info.get('username', '?')}",
                                        f"  Password: {vm_info.get('root_password', '--')}",
                                        "",
                                    ]
                                    with open(_log_path, "a", encoding="utf-8") as _lf:
                                        _lf.write("\n".join(_lines) + "\n")
                                except Exception:
                                    pass

                                print(f"\n{'='*60}")
                                print(f"  SCRIPT COMPLETED SUCCESSFULLY!")
                                print(f"  FOUND IP WITH PREFIX {cidrs_display}!")
                                print(f"  Zone: {current_zone}")
                                print(f"  VM: {vm_info.get('instance_id', vm_info.get('server_id', '?'))}")
                                print(f"  IP: {vm_info['ip']}")
                                print(f"{'='*60}\n")

                                # Wait for background deletions
                                ip_deleter.wait_all(timeout=30)
                                return vm_info
                            else:
                                print(f"  VM creation failed for IP {fip_addr}")
                                self.delete_floating_ip(fip_id, silent=True)
                        else:
                            print(f" -- не подходит")
                            # Schedule background delete with delay
                            if fip_id in self.created_floating_ips:
                                self.created_floating_ips.remove(fip_id)
                            ip_deleter.schedule(fip_id, fip_addr)

                        # Intra-session delay
                        delay = random.randint(profile["base_delay_min"], profile["base_delay_max"])
                        if delay > 0:
                            time.sleep(delay)

                    # ─── End of session ───
                    if total_attempts < profile["max_total_attempts"]:
                        pause = random.randint(profile["session_pause_min"], profile["session_pause_max"])
                        print(f"\n  Пауза между сессиями: {pause}с")
                        time.sleep(pause)
                        zone_index += 1

                # ─── Max attempts reached → sleep and reset ───
                sleep_min = profile["reset_sleep_minutes"]
                print(f"\n{'='*60}")
                print(f"  Достигнут лимит попыток ({profile['max_total_attempts']})")
                print(f"  Найдено IP: {found_ips}")
                print(f"  Сон: {sleep_min} мин")
                print(f"{'='*60}")

                # Wait for background deletions before sleeping
                ip_deleter.wait_all(timeout=60)

                time.sleep(sleep_min * 60)

                print(f"\n  Проснулся! Сброс счётчика, начинаю заново...")
                zone_index += 1

        except KeyboardInterrupt:
            print("\n\n  Прервано пользователем. Очистка...")
            ip_deleter.wait_all(timeout=30)
            try:
                self.cleanup_all()
            except Exception:
                pass
            return None


# ---- SSH Utilities ----

def wait_for_ssh(host: str, username: str, private_key_path: str,
                 port: int = 22, timeout: int = 120) -> bool:
    """Wait for SSH to become available."""
    if not paramiko:
        return False
    key_path = Path(private_key_path)
    if not key_path.exists():
        return False

    import logging
    _paramiko_log = logging.getLogger("paramiko")
    _old_level = _paramiko_log.level
    _paramiko_log.setLevel(logging.CRITICAL)
    try:
        time.sleep(15)
        start = time.time()
        while time.time() - start < timeout:
            try:
                key = paramiko.Ed25519Key.from_private_key_file(str(key_path))
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                _sock = _make_proxy_sock(host, port)
                client.connect(host, port=port, username=username, pkey=key,
                               timeout=10, banner_timeout=15, sock=_sock)
                client.close()
                return True
            except Exception:
                time.sleep(5)
        return False
    finally:
        _paramiko_log.setLevel(_old_level)


def _try_connect_by_password_plink(host, root_user, root_password, port=22, timeout=15):
    if platform.system() != "Windows":
        return False
    plink_paths = [r"C:\Program Files\PuTTY\plink.exe",
                   r"C:\Program Files (x86)\PuTTY\plink.exe", "plink"]
    plink_cmd = None
    for p in plink_paths:
        if p == "plink" or Path(p).exists():
            plink_cmd = p
            break
    if not plink_cmd:
        return False
    try:
        result = subprocess.run(
            [plink_cmd, "-ssh", "-batch", "-P", str(port), "-l", root_user,
             "-pw", root_password, host, "echo", "OK"],
            capture_output=True, timeout=timeout, text=True)
        return result.returncode == 0
    except Exception:
        return False


def try_connect_by_password(host, root_user, root_password, port=22, timeout=15):
    if platform.system() == "Windows" and _try_connect_by_password_plink(
            host, root_user, root_password, port, timeout):
        return True
    if paramiko:
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            _sock = _make_proxy_sock(host, port)
            client.connect(host, port=port, username=root_user, password=root_password,
                           timeout=timeout, banner_timeout=timeout, auth_timeout=timeout, sock=_sock)
            client.close()
            return True
        except Exception as e:
            err_str = str(e).lower()
            if "unimplemented" in err_str or "type 3" in err_str:
                if _try_connect_by_password_plink(host, root_user, root_password, port, timeout):
                    return True
            return False
    return _try_connect_by_password_plink(host, root_user, root_password, port, timeout)


def _ssh_run_subprocess(host, port, username, private_key_path, remote_cmd, timeout=45):
    key_path = Path(private_key_path)
    if not key_path.exists():
        return False
    args = ["ssh", "-i", str(key_path), "-o", "StrictHostKeyChecking=no",
            "-o", "BatchMode=yes", "-p", str(port), f"{username}@{host}", remote_cmd]
    try:
        r = subprocess.run(args, timeout=timeout, capture_output=True, text=True)
        return r.returncode == 0
    except Exception:
        return False


def ensure_root_password_login_works(host, username, private_key_path, port=22):
    """Set up root password login via SSH key."""
    key_path = Path(private_key_path)
    if not key_path.exists():
        return None
    root_password = secrets.token_urlsafe(12)
    safe_pass = root_password.replace("'", "'\"'\"'")

    cmd_99 = (
        "tee /etc/ssh/sshd_config.d/99-local.conf << 'EOF'\n"
        "PasswordAuthentication yes\n"
        "ChallengeResponseAuthentication yes\n"
        "PermitRootLogin yes\n"
        "EOF"
    )
    if not _ssh_run_subprocess(host, port, username, private_key_path, cmd_99, timeout=15):
        print("  Failed to create 99-local.conf")
        return None
    print("  Created /etc/ssh/sshd_config.d/99-local.conf")

    cmd_chpasswd = f"echo 'root:{safe_pass}' | chpasswd"
    if not _ssh_run_subprocess(host, port, username, private_key_path, cmd_chpasswd, timeout=15):
        print("  Failed to set root password")
        return None
    print("  Root password set")

    if not _ssh_run_subprocess(host, port, username, private_key_path,
                                "systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || service ssh restart",
                                timeout=15):
        print("  SSH restart failed, continuing")
    time.sleep(10)

    for attempt in range(6):
        if try_connect_by_password(host, "root", root_password, port=port, timeout=12):
            print("  Password login verified")
            return root_password
        if attempt < 5:
            time.sleep(5)
    print("  Password login verification failed")
    return None


# ---- Telegram ----

def _build_telegram_message(vm_info):
    ip = vm_info.get("ip", "N/A")
    ssh_port = vm_info.get("ssh_port", 22)
    root_login = vm_info.get("root_login", "")
    root_password = vm_info.get("root_password", "")
    account_name = vm_info.get("account_name", "")
    account_folder_id = vm_info.get("account_folder_id", "")
    account_proxy = vm_info.get("account_proxy", "")
    account_id = vm_info.get("account_id", "")

    header = ""
    if account_name:
        label = f"#{account_id} " if account_id != "" else ""
        header += f"<b>Account:</b> {label}<code>{account_name}</code>\n"
    if account_folder_id:
        header += f"<b>Project:</b> <code>{account_folder_id}</code>\n"
    if account_proxy:
        header += f"<b>Proxy:</b> <code>{account_proxy}</code>\n"
    if header:
        header += "\n"

    message = (
        header +
        f"<b>IP:</b> <code>{ip}</code>\n"
        f"<b>Port:</b> <code>{ssh_port}</code>\n\n"
    )
    if root_login and root_password:
        message += (
            "<b>Password login:</b>\n"
            f"  Host: <code>{ip}</code>\n"
            f"  Login: <code>{root_login}</code>\n"
            f"  Password: <code>{root_password}</code>\n\n"
            f"Connect: <code>ssh {root_login}@{ip}</code>"
        )
    return message


def _try_send_telegram(bot_token, chat_id, message, proxy=None, label=""):
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {"chat_id": chat_id, "text": message, "parse_mode": "HTML"}

    if proxy:
        proxy_url = f"socks5h://{proxy}" if "://" not in proxy else proxy
        proxies = {"http": proxy_url, "https": proxy_url}
    else:
        proxies = {"http": "", "https": ""}

    try:
        response = _req_post(url, json=payload, timeout=15, proxies=proxies)
        if response.status_code == 200:
            if label:
                print(f"    Sent ({label})")
            return True
        else:
            if label:
                print(f"    HTTP {response.status_code} ({label})")
    except Exception as e:
        if label:
            print(f"    {e} ({label})")
    return False


def send_telegram_notification(vm_info, bot_token, chat_id):
    if not bot_token or not chat_id:
        return False
    message = _build_telegram_message(vm_info)
    account_proxy = vm_info.get("account_proxy", "")

    if account_proxy:
        print(f"  Attempt 1: via account proxy...")
        if _try_send_telegram(bot_token, chat_id, message, proxy=account_proxy, label="account proxy"):
            return True

    print(f"  Attempt 2: direct...")
    if _try_send_telegram(bot_token, chat_id, message, proxy=None, label="direct"):
        return True

    db_path = os.environ.get('VK_DB_PATH', str(Path(__file__).parent / 'launcher' / 'data' / 'launcher.db'))
    if Path(db_path).exists():
        try:
            from db import load_config_from_db
            config = load_config_from_db(db_path)
            other_proxies = []
            for acc in config.get("accounts", []):
                p = acc.get("proxy", "")
                if p and p != account_proxy and p not in other_proxies:
                    other_proxies.append(p)
            for i, proxy in enumerate(other_proxies):
                print(f"  Attempt {3 + i}: via proxy ({proxy.split('@')[-1]})...")
                if _try_send_telegram(bot_token, chat_id, message, proxy=proxy, label=f"proxy #{i+1}"):
                    return True
        except Exception:
            pass

    print("  All Telegram attempts exhausted")
    return False


def send_notification(vm_info, telegram_config=None):
    ip = vm_info.get("ip", "N/A")
    instance_id = vm_info.get("instance_id", vm_info.get("server_id", "N/A"))
    zone = vm_info.get("zone", "N/A")

    print("\n" + "!" * 80)
    print(" " * 20 + "FOUND IP WITH TARGET PREFIX!")
    print(" " * 20 + "SCRIPT STOPPING!")
    print("!" * 80)
    print(f"\n{'':>25}IP: {ip}")
    print(f"{'':>25}VM ID: {instance_id}")
    print(f"{'':>25}Zone: {zone}")
    print("!" * 80 + "\n")

    if platform.system() == "Windows":
        try:
            import winsound
            for _ in range(3):
                winsound.MessageBeep(winsound.MB_ICONEXCLAMATION)
                time.sleep(0.3)
        except Exception:
            pass

    db_path = os.environ.get('VK_DB_PATH', str(Path(__file__).parent / 'launcher' / 'data' / 'launcher.db'))

    if Path(db_path).exists():
        try:
            from db import save_found_vm
            if save_found_vm(vm_info, db_path):
                print(f"  VM saved to SQLite DB")
        except Exception as e:
            print(f"  DB save error: {e}")

    if telegram_config:
        bot_token = telegram_config.get("bot_token")
        chat_id = telegram_config.get("chat_id")
        if bot_token and chat_id:
            print("Sending Telegram notification...")
            tg_sent = send_telegram_notification(vm_info, bot_token, chat_id)
            if tg_sent:
                print("  Telegram notification sent")
                if Path(db_path).exists():
                    try:
                        from db import mark_telegram_sent
                        mark_telegram_sent(vm_info.get("instance_id") or vm_info.get("ip", ""), db_path)
                    except Exception:
                        pass
            else:
                print("  Telegram notification failed")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    result_file = Path(__file__).parent / f"found_vm_{timestamp}.json"
    try:
        with open(result_file, 'w', encoding='utf-8') as f:
            json.dump(vm_info, f, indent=2, ensure_ascii=False)
        print(f"  Saved to {result_file}")
    except Exception as e:
        print(f"  Error saving to file: {e}")

    print_ssh_connection_info(vm_info)


# ---- SSH Key Generation ----

def generate_ssh_key_pair(key_name=None):
    script_dir = Path(__file__).parent
    keys_dir = script_dir / "ssh_keys"
    keys_dir.mkdir(exist_ok=True)

    if not key_name:
        timestamp = int(time.time())
        key_name = f"vm_key_{timestamp}_{os.getpid()}"

    private_key_path = keys_dir / f"{key_name}"
    public_key_path = keys_dir / f"{key_name}.pub"

    try:
        if platform.system() == "Windows":
            ssh_keygen_cmd = "ssh-keygen"
            result = subprocess.run(["where", "ssh-keygen"], capture_output=True, text=True, timeout=5)
            if result.returncode != 0:
                possible_paths = [
                    r"C:\Windows\System32\OpenSSH\ssh-keygen.exe",
                    r"C:\Program Files\Git\usr\bin\ssh-keygen.exe",
                ]
                ssh_keygen_cmd = None
                for p in possible_paths:
                    if Path(p).exists():
                        ssh_keygen_cmd = p
                        break
                if not ssh_keygen_cmd:
                    raise FileNotFoundError("ssh-keygen not found")
        else:
            ssh_keygen_cmd = "ssh-keygen"

        subprocess.run(
            [ssh_keygen_cmd, "-t", "ed25519", "-f", str(private_key_path),
             "-N", "", "-C", f"vkcloud-vm-{key_name}"],
            check=True, capture_output=True, timeout=30
        )

        with open(public_key_path, 'r', encoding='utf-8') as f:
            public_key = f.read().strip()

        if platform.system() != "Windows":
            os.chmod(private_key_path, 0o600)

        return {
            "private_key_path": str(private_key_path),
            "public_key_path": str(public_key_path),
            "public_key": public_key,
            "key_name": key_name
        }
    except subprocess.CalledProcessError as e:
        raise Exception(f"SSH key generation error: {e.stderr.decode() if e.stderr else str(e)}")
    except FileNotFoundError as e:
        raise Exception(f"ssh-keygen not found: {e}")


def print_ssh_connection_info(vm_info):
    ip = vm_info.get("ip", "N/A")
    username = vm_info.get("username", "root")
    private_key_path = vm_info.get("private_key_path", "N/A")
    zone = vm_info.get("zone", "N/A")
    instance_id = vm_info.get("instance_id", vm_info.get("server_id", "N/A"))
    ssh_port = vm_info.get("ssh_port", 22)
    root_login = vm_info.get("root_login", "")
    root_password = vm_info.get("root_password", "")

    print("\n" + "=" * 80)
    print(" " * 25 + "SSH CONNECTION INFO")
    print("=" * 80)
    print(f"  IP:        {ip}")
    print(f"  Port:      {ssh_port}")
    print(f"  Zone:      {zone}")
    print(f"  VM ID:     {instance_id}")
    if root_login and root_password:
        print(f"\n  Password login:")
        print(f"     Login:    {root_login}")
        print(f"     Password: {root_password}")
        print(f"     Command:  ssh {root_login}@{ip}")
    print(f"\n  Key login: ssh -i \"{private_key_path}\" {username}@{ip}")
    print("=" * 80 + "\n")


# ---- DB Helper ----

def load_config_from_db_direct(db_path):
    """Load config directly from SQLite (without importing db module)."""
    import sqlite3
    config = {}
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute("SELECT key, value FROM config")
        for row in cursor.fetchall():
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

        cursor.execute("SELECT * FROM accounts ORDER BY id")
        accounts = []
        for row in cursor.fetchall():
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
    except Exception as e:
        print(f"  DB load error: {e}")
    return config


# ---- Config Loading ----

def load_config():
    """Load configuration from SQLite DB and/or environment variables."""
    config = {
        "username": None,
        "password": None,
        "project_id": None,
        "zone": "MS1",
        "target_cidrs": "95.163",
        "profile": "balanced",
        "batch_size": 7,
        "flavor_id": None,
        "image_id": None,
        "network_id": None,
    }

    config_dir = Path(__file__).parent

    # Load from SQLite DB
    db_path = os.environ.get('VK_DB_PATH', str(config_dir / 'launcher' / 'data' / 'launcher.db'))
    if Path(db_path).exists():
        try:
            db_config = load_config_from_db_direct(db_path)
            if db_config:
                config.update(db_config)
                print(f"  Config loaded from SQLite DB")
        except Exception as e:
            print(f"  DB load error: {e}")

    # Multi-account: if VK_ACCOUNT_ID is set, use that account
    account_id_env = os.getenv("VK_ACCOUNT_ID")
    if account_id_env is not None:
        try:
            acc_id = int(account_id_env)
            accounts = config.get("accounts", [])
            acc = next((a for a in accounts if a.get('id') == acc_id), None)
            if acc:
                print(f"  Account #{acc_id}: {acc.get('name') or acc.get('project_id', '?')}")
                if acc.get("username"):
                    config["username"] = acc["username"]
                if acc.get("password"):
                    config["password"] = acc["password"]
                if acc.get("project_id"):
                    config["project_id"] = acc["project_id"]
                config["account_name"] = acc.get("name") or acc.get("project_id", "")
                config["account_folder_id"] = acc.get("project_id", "")
                config["account_proxy"] = acc.get("proxy", "")
                config["account_id"] = acc_id
            else:
                print(f"  Account #{acc_id} not found in DB")
        except ValueError:
            print(f"  Invalid VK_ACCOUNT_ID: {account_id_env}")

    # Environment variables override
    config["username"] = os.getenv("VK_USERNAME", config.get("username"))
    config["password"] = os.getenv("VK_PASSWORD", config.get("password"))
    config["project_id"] = os.getenv("VK_PROJECT_ID", config.get("project_id"))
    config["target_cidrs"] = os.getenv("VK_TARGET_CIDRS", config.get("target_cidrs", config.get("target_ip_prefix", "95.163")))
    config["profile"] = os.getenv("VK_PROFILE", config.get("profile", "balanced"))
    config["zone"] = os.getenv("VK_ZONE", config.get("zone", "MS1"))
    config["flavor_id"] = os.getenv("VK_FLAVOR_ID", config.get("flavor_id"))
    config["image_id"] = os.getenv("VK_IMAGE_ID", config.get("image_id"))
    config["network_id"] = os.getenv("VK_NETWORK_ID", config.get("network_id"))

    batch_env = os.getenv("VK_BATCH_SIZE")
    if batch_env:
        try:
            config["batch_size"] = int(batch_env)
        except ValueError:
            pass

    return config


def main():
    config = load_config()

    USERNAME = config.get("username")
    PASSWORD = config.get("password")
    PROJECT_ID = config.get("project_id")
    ZONE = config.get("zone", "MS1")
    TARGET_CIDRS_STR = config.get("target_cidrs", "95.163")
    PROFILE_KEY = config.get("profile", "balanced")
    FLAVOR_ID = config.get("flavor_id")
    IMAGE_ID = config.get("image_id")
    NETWORK_ID = config.get("network_id")

    if not USERNAME or not PASSWORD or not PROJECT_ID:
        print("  ERROR: VK_USERNAME, VK_PASSWORD, VK_PROJECT_ID are required")
        print("\n  Set via environment variables or launcher config:")
        print("    VK_USERNAME - email for VK Cloud")
        print("    VK_PASSWORD - password")
        print("    VK_PROJECT_ID - project ID")
        return

    if not FLAVOR_ID or not IMAGE_ID or not NETWORK_ID:
        print("  ERROR: VK_FLAVOR_ID, VK_IMAGE_ID, VK_NETWORK_ID are required")
        print("\n  Set via environment variables or launcher config:")
        print("    VK_FLAVOR_ID - flavor (instance type) ID")
        print("    VK_IMAGE_ID - OS image ID")
        print("    VK_NETWORK_ID - network ID")
        return

    # Parse target CIDRs
    target_cidrs = parse_cidrs(TARGET_CIDRS_STR)
    if not target_cidrs:
        print("  ERROR: No target CIDRs specified")
        return

    # Validate profile
    profile = get_profile(PROFILE_KEY)

    # Generate SSH key
    print("\nGenerating SSH key for this session...")
    session_ssh_info = None
    try:
        ssh_key_info = generate_ssh_key_pair()
        print(f"  SSH key: {ssh_key_info['key_name']}")
        print(f"  Private: {ssh_key_info['private_key_path']}")
        session_ssh_info = {
            "private_key_path": ssh_key_info["private_key_path"],
            "public_key_path": ssh_key_info["public_key_path"],
            "username": "root",
        }
    except Exception as e:
        print(f"  SSH key generation failed: {e}")
        print("  Continuing without SSH key...")

    # Zones
    zones = [ZONE]
    zones_config = config.get("zones")
    if zones_config and isinstance(zones_config, list):
        zones = zones_config
    elif ZONE:
        zones = [ZONE]

    if os.getenv("VK_NON_INTERACTIVE") or not sys.stdin.isatty():
        print(f"\n  Zones (non-interactive): {', '.join(zones)}")
    else:
        print(f"\n  Zone: {', '.join(zones)}")

    print(f"\n{'='*60}")
    print("Configuration:")
    print(f"  Profile: {profile['name']} ({PROFILE_KEY})")
    print(f"  Target CIDRs: {', '.join(target_cidrs)}")
    print(f"  Max attempts: {profile['max_total_attempts']}")
    print(f"  Sleep time: {profile['reset_sleep_minutes']} min")
    print(f"  Zone(s): {', '.join(zones)}")
    print(f"  Flavor: {FLAVOR_ID}")
    print(f"  Image: {IMAGE_ID}")
    print(f"  Network: {NETWORK_ID}")
    print(f"{'='*60}\n")

    # Create client
    client = VKCloudVM(
        username=USERNAME,
        password=PASSWORD,
        project_id=PROJECT_ID,
        zone=zones[0] if zones else "MS1",
    )

    # Telegram config
    telegram_config = None
    tg_bot = config.get("telegram_bot_token")
    tg_chat = config.get("telegram_chat_id")
    if tg_bot and tg_chat:
        telegram_config = {"bot_token": tg_bot, "chat_id": tg_chat}

    # Account info
    account_info = {
        "account_name": config.get("account_name", ""),
        "account_folder_id": config.get("account_folder_id", config.get("project_id", "")),
        "account_proxy": config.get("account_proxy", ""),
        "account_id": config.get("account_id", ""),
        "project_id": PROJECT_ID,
    }

    # Cleanup existing servers
    print("Checking existing servers...")
    protected_ids = set()

    # Check for existing servers with target IP
    servers = client.list_servers(silent=True)
    for srv in servers:
        srv_ip = client.get_server_ip(srv)
        if srv_ip and is_target_ip(srv_ip, target_cidrs):
            protected_ids.add(srv["id"])
            print(f"  Protected server: {srv['id'][:12]}... ({srv_ip})")

    deleted = client.cleanup_all_project_servers(exclude_ids=list(protected_ids))
    if deleted > 0:
        print(f"  Freed quota ({deleted} servers)")

    # Hunt!
    result = client.hunt_target_ip(
        image_id=IMAGE_ID,
        flavor_id=FLAVOR_ID,
        network_id=NETWORK_ID,
        target_cidrs=target_cidrs,
        profile_key=PROFILE_KEY,
        zones=zones,
        telegram_config=telegram_config,
        ssh_info=session_ssh_info,
        account_info=account_info,
    )

    if result:
        print(f"\n  SUCCESS! Found VM with IP {result['ip']}")
    else:
        print("\n  No matching VM found (interrupted or error)")


if __name__ == "__main__":
    main()
