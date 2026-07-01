"""
config.py - Configuration & Noise Filtering System
LNSM System - B00971364
"""

import ipaddress
import json
import os
import threading
from pathlib import Path

CONFIG_PATH = os.environ.get("LNSM_CONFIG_PATH", str(Path(__file__).with_name("lnsm_settings.json")))

DEFAULT_IGNORED_PREFIXES = (
    # 1. Ignore common Windows/Microsoft/Google telemetry and content networks
    "20.190.", "20.189.", "20.86.", "52.96.", "52.97.", "52.107.", "104.208.", "13.107.", "40.96.", "135.234.",
    # 2. Ignore Google IPs
    "34.", "142.250.", "142.251.", "172.217.", "216.", "151.101.", "199.232.", "104.",
    # 3. Ignore common internal subnets
    "10.", "192.168.", "172.16.", "172.31.", "169.254.",
    # 4. Localhost
    "127.",
    # 5. Virgin Media / Local DNS
    "194.168.4."
)

DEFAULT_SETTINGS = {
    "safe_mode": False,
    "ignored_ips": ["127.0.0.1", "192.168.0.1", "192.168.1.1", "10.0.0.1"],
    "ignored_prefixes": ["20.190.", "52.96.", "142.250.", "172.217.", "151.101."],
}


_cached_settings = None
_settings_lock = threading.Lock()

def load_settings(force_reload=False):
    """
    Loads application settings from the JSON configuration file.
    
    Uses thread-safe caching to minimize disk I/O when the configuration
    is requested frequently (e.g., during packet processing).
    
    Args:
        force_reload (bool): Bypass the cache and reload from disk.
        
    Returns:
        dict: The loaded configuration dictionary.
    """
    global _cached_settings
    if _cached_settings is not None and not force_reload:
        return dict(_cached_settings)

    with _settings_lock:
        if not os.path.exists(CONFIG_PATH):
            _cached_settings = dict(DEFAULT_SETTINGS)
            return dict(_cached_settings)
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as fh:
                data = json.load(fh)
                if not isinstance(data, dict):
                    _cached_settings = dict(DEFAULT_SETTINGS)
                    return dict(_cached_settings)
                settings = dict(DEFAULT_SETTINGS)
                settings.update(data)
                settings["ignored_ips"] = list(settings.get("ignored_ips", []))
                settings["ignored_prefixes"] = list(settings.get("ignored_prefixes", []))
                _cached_settings = settings
                return dict(_cached_settings)
        except Exception:
            _cached_settings = dict(DEFAULT_SETTINGS)
            return dict(_cached_settings)


def save_settings(settings):
    """
    Saves the application settings back to the JSON configuration file
    and updates the in-memory cache.
    
    Args:
        settings (dict): The configuration dictionary to save.
    """
    global _cached_settings
    with _settings_lock:
        with open(CONFIG_PATH, "w", encoding="utf-8") as fh:
            json.dump(settings, fh, indent=2)
        _cached_settings = dict(settings)


def is_ignored_ip(ip):
    """
    Evaluates whether an IP address should be ignored (filtered) based on
    whitelists, common telemetry networks, and local subnet rules.
    
    Args:
        ip (str): The IP address to evaluate.
        
    Returns:
        bool: True if the IP is benign and should be ignored, False if it is 
              potentially hostile.
    """
    if not ip:
        return False

    settings = load_settings()
    ignored_ips = set(settings.get("ignored_ips", []))
    ignored_prefixes = tuple(settings.get("ignored_prefixes", [])) + DEFAULT_IGNORED_PREFIXES

    if ip in ignored_ips:
        return True

    if isinstance(ip, str) and any(ip.startswith(prefix) for prefix in ignored_prefixes):
        return True

    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return False

    if ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_reserved:
        return True

    if settings.get("safe_mode", True) and ip_obj.is_private:
        return True

    return False


def add_ignored_entry(value):
    settings = load_settings()
    values = settings.setdefault("ignored_ips", [])
    if value not in values:
        values.append(value)
    save_settings(settings)
    return settings


def remove_ignored_entry(value):
    settings = load_settings()
    values = settings.setdefault("ignored_ips", [])
    if value in values:
        values.remove(value)
    save_settings(settings)
    return settings


def set_safe_mode(enabled):
    settings = load_settings()
    settings["safe_mode"] = bool(enabled)
    save_settings(settings)
    return settings
