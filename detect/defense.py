#!/usr/bin/env python3
"""
ARP Spoofing Defense Module - detect.py ile kullanım için.
"""

import subprocess
import platform
import re
from typing import Optional
import logging


def get_default_interface() -> str:
    """Varsayılan ağ arayüzünü tespit eder (Windows, Linux, macOS)."""
    system = platform.system().lower()
    
    if system == "windows":
        try:
            output = subprocess.check_output(
                ["netsh", "interface", "show", "interface"],
                text=True, errors="ignore"
            )
            for line in output.splitlines():
                if "Connected" in line or "Bağlı" in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        name = parts[-1]
                        if "wi-fi" in name.lower() or "wireless" in name.lower():
                            return name
            for line in output.splitlines():
                if "Connected" in line or "Bağlı" in line:
                    return line.split()[-1]
        except Exception:
            pass
        return "Wi-Fi"

    elif system == "darwin":  # macOS
        try:
            # macOS'te route komutu interface'i de verir (interface: en0)
            output = subprocess.check_output(["route", "-n", "get", "default"]).decode()
            match = re.search(r'interface:\s+(\S+)', output)
            if match:
                return match.group(1)
        except Exception:
            pass
        return "en0"  # Fallback
    
    else: # Linux
        try:
            output = subprocess.check_output(["ip", "route"]).decode()
            for line in output.splitlines():
                if line.startswith("default") and "dev" in line:
                    parts = line.split()
                    return parts[parts.index("dev") + 1]
        except Exception:
            pass
    
    return "wlan0" # Fallback


class ARPDefender:
    """ARP Spoofing savunma mekanizmaları."""
    
    def __init__(self, gateway_ip: str, original_mac: str, 
                 logger: logging.Logger, interface: str = None):
        self.gateway_ip = gateway_ip
        self.original_mac = original_mac
        self.logger = logger
        self.interface = interface or get_default_interface()
        self.system = platform.system().lower()
        self.blocked_macs = set()
    
    def _run(self, cmd: list) -> subprocess.CompletedProcess:
        """Subprocess wrapper."""
        return subprocess.run(cmd, capture_output=True, text=True)
    
    # === SAVUNMA 1: Statik ARP ===
    
    def apply_static_arp(self) -> bool:
        """Gateway için statik ARP girişi ekler."""
        self.logger.info(f"[DEFENSE] Statik ARP: {self.gateway_ip} -> {self.original_mac}")
        
        try:
            if self.system == "windows":
                self._run(["netsh", "interface", "ip", "delete", "neighbors",
                          "interface=*", f"address={self.gateway_ip}"])
                iface = self._get_win_interface()
                result = self._run(["netsh", "interface", "ip", "add", "neighbors",
                                   f"interface={iface}", f"address={self.gateway_ip}",
                                   f"neighbor={self.original_mac.replace(':', '-')}"])
            else:
                self._run(["sudo", "arp", "-d", self.gateway_ip])
                result = self._run(["sudo", "arp", "-s", self.gateway_ip, self.original_mac])
            
            if result.returncode == 0:
                self.logger.info("[DEFENSE] ✓ Statik ARP eklendi!")
                return True
            self.logger.error(f"[DEFENSE] ✗ Statik ARP başarısız: {result.stderr}")
            return False
        except Exception as e:
            self.logger.error(f"[DEFENSE] Hata: {e}")
            return False
    
    def remove_static_arp(self) -> bool:
        """Statik ARP girişini kaldırır."""
        try:
            if self.system == "windows":
                self._run(["netsh", "interface", "ip", "delete", "neighbors",
                          "interface=*", f"address={self.gateway_ip}"])
            else:
                self._run(["sudo", "arp", "-d", self.gateway_ip])
            self.logger.info("[DEFENSE] Statik ARP kaldırıldı.")
            return True
        except Exception:
            return False
    
    def _get_win_interface(self) -> str:
        """Windows interface adı."""
        try:
            output = subprocess.check_output(
                ["netsh", "interface", "show", "interface"], text=True)
            for line in output.splitlines():
                if "Connected" in line:
                    return line.split()[-1]
        except Exception:
            pass
        return "Wi-Fi"
        
    # === SAVUNMA 3: MAC Engelleme (Linux) ===
    
    def block_attacker_mac(self, attacker_mac: str) -> bool:
        """Saldırgan MAC'ini iptables ile engeller."""
        if self.system == "windows":
            return False
        
        if attacker_mac in self.blocked_macs:
            return True
        
        self.logger.info(f"[DEFENSE] Engelleniyor: {attacker_mac}")
        
        try:
            r1 = self._run(["sudo", "iptables", "-A", "INPUT", "-m", "mac",
                           "--mac-source", attacker_mac, "-j", "DROP"])
            
            if r1.returncode == 0:
                self.blocked_macs.add(attacker_mac)
                self.logger.info(f"[DEFENSE] ✓ {attacker_mac} engellendi!")
                return True
            return False
        except Exception:
            return False
    
    def _unblock_mac(self, mac: str):
        """MAC engelini kaldır."""
        if self.system == "windows" or mac not in self.blocked_macs:
            return
        try:
            self._run(["sudo", "iptables", "-D", "INPUT", "-m", "mac",
                      "--mac-source", mac, "-j", "DROP"])
            self._run(["sudo", "iptables", "-D", "FORWARD", "-m", "mac",
                      "--mac-source", mac, "-j", "DROP"])
            self.blocked_macs.discard(mac)
        except Exception:
            pass
    
    # === SAVUNMA 4: Ağ Kesme (Son Çare) ===
    
    def disable_network(self) -> bool:
        """Ağ arayüzünü kapatır."""
        self.logger.critical("[DEFENSE] ⚠️ AĞ KAPATILIYOR!")
        
        try:
            if self.system == "windows":
                result = self._run(["netsh", "interface", "set", "interface",
                                   self._get_win_interface(), "disable"])
            else:
                result = self._run(["sudo", "ip", "link", "set", self.interface, "down"])
            return result.returncode == 0
        except Exception:
            return False
    
    # === OTOMATİK SAVUNMA ===
    
    def auto_defend(self, detected_mac: str, severity: str = "medium"):
        """Şiddet seviyesine göre savunma uygular."""
        self.logger.warning(f"[DEFENSE] Otomatik savunma: {severity}")
        
        self.apply_static_arp()
        
        if severity in ["medium", "high", "critical"]:
            self.block_attacker_mac(detected_mac)
        
        if severity == "critical":
            self.disable_network()
    
    def cleanup(self):
        """Temizlik."""
        self.logger.info("[DEFENSE] Temizlik...")
        for mac in list(self.blocked_macs):
            self._unblock_mac(mac)
        self.remove_static_arp()
