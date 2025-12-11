#!/usr/bin/env python3
"""
ARP Spoofing Defense Module - detect.py ile kullanım için.
Düzeltmeler: MAC Normalizasyonu (0 -> 00) ve macOS uyumluluğu.
"""

import subprocess
import platform
import re
import logging
import shutil

class ARPDefender:
    """ARP Spoofing savunma mekanizmaları."""
    
    def __init__(self, gateway_ip: str, original_mac: str, 
                 logger: logging.Logger, interface: str = None):
        self.gateway_ip = gateway_ip
        # Gelen MAC adresini anında fixle (örn: 0 -> 00)
        self.original_mac = self._normalize_mac(original_mac)
        self.logger = logger
        self.system = platform.system().lower()
        self.interface = interface or self._get_default_interface()
        self.blocked_macs = set()
        
        # arp komutunun tam yolunu bul (macOS için önemli)
        self.arp_cmd = shutil.which("arp") or "/usr/sbin/arp"

    def _normalize_mac(self, mac: str) -> str:
        """
        MAC adresini işletim sisteminin seveceği 00:11:22... formatına çevirir.
        Özellikle macOS'in '0' çıktılarını '00' yapar.
        """
        if not mac: return ""
        try:
            # Temizle
            clean_mac = mac.strip().replace("-", ":").lower()
            parts = clean_mac.split(":")
            
            # Eğer 6 parça varsa (geçerli bir MAC ise)
            if len(parts) == 6:
                # Her parçayı 2 haneye tamamla (zfill)
                return ":".join([p.zfill(2) for p in parts])
            return clean_mac
        except Exception:
            return mac

    def _run(self, cmd: list) -> subprocess.CompletedProcess:
        """Komut çalıştırma yardımcısı."""
        # None olan argümanları temizle ve string'e çevir
        cmd = [str(c) for c in cmd if c is not None]
        return subprocess.run(cmd, capture_output=True, text=True)
    
    def _get_default_interface(self) -> str:
        """İşletim sistemine göre aktif ağ arayüzünü bulur."""
        if self.system == "windows":
            return "Wi-Fi"
        elif self.system == "darwin":  # macOS
            try:
                # macOS route tablosundan interface'i çeker
                out = subprocess.check_output(["route", "-n", "get", "default"], stderr=subprocess.DEVNULL).decode()
                m = re.search(r'interface:\s+(\S+)', out)
                return m.group(1) if m else "en0"
            except:
                return "en0"
        else: # Linux
            try:
                out = subprocess.check_output(["ip", "route"], stderr=subprocess.DEVNULL).decode()
                m = re.search(r'default via .+ dev (\S+)', out)
                return m.group(1) if m else "eth0"
            except:
                return "eth0"

    # === SAVUNMA 1: Statik ARP (En Önemli Kısım) ===
    
    def apply_static_arp(self) -> bool:
        """
        Gateway MAC adresini statik olarak sabitler.
        Bu işlem Spoofing saldırısını etkisiz hale getirir.
        """
        self.logger.info(f"[DEFENSE] Statik ARP Uygulanıyor: {self.gateway_ip} -> {self.original_mac}")
        
        try:
            if self.system == "windows":
                self._run(["netsh", "interface", "ip", "delete", "neighbors",
                          "interface=*", f"address={self.gateway_ip}"])
                
                result = self._run(["netsh", "interface", "ip", "add", "neighbors",
                                   f"interface={self.interface}", f"address={self.gateway_ip}",
                                   f"neighbor={self.original_mac.replace(':', '-')}"])
            else:
                # macOS ve Linux
                # 1. Mevcut (zehirli) kaydı sil
                self._run(["sudo", self.arp_cmd, "-d", self.gateway_ip])
                
                # 2. Doğru MAC adresini 'permanent' (kalıcı) olarak ekle
                result = self._run(["sudo", self.arp_cmd, "-s", self.gateway_ip, self.original_mac])
            
            if result.returncode == 0:
                self.logger.info("[DEFENSE] ✓ Statik ARP başarıyla eklendi! (Saldırı Engellendi)")
                return True
            else:
                self.logger.error(f"[DEFENSE] ✗ Statik ARP hatası: {result.stderr.strip()}")
                return False

        except Exception as e:
            self.logger.error(f"[DEFENSE] Kritik Hata: {e}")
            return False
    
    def remove_static_arp(self) -> bool:
        """Program kapanırken statik ARP kaydını siler."""
        try:
            if self.system == "windows":
                self._run(["netsh", "interface", "ip", "delete", "neighbors",
                          "interface=*", f"address={self.gateway_ip}"])
            else:
                # macOS/Linux: sudo arp -d IP
                self._run(["sudo", self.arp_cmd, "-d", self.gateway_ip])
            self.logger.info("[DEFENSE] Statik ARP temizlendi, normale dönüldü.")
            return True
        except Exception:
            return False

    # === SAVUNMA 3: MAC Engelleme (Linux Only) ===
    
    def block_attacker_mac(self, attacker_mac: str) -> bool:
        """
        Saldırganı engeller.
        macOS'te iptables olmadığı için sadece uyarı verir.
        """
        if self.system != "linux":
            if attacker_mac not in self.blocked_macs:
                 self.logger.info(f"[DEFENSE] Not: macOS üzerinde MAC engelleme (firewall) pasif.")
                 self.logger.info(f"[DEFENSE] Merak etmeyin, Statik ARP saldırıyı zaten durdurdu! 🛡️")
                 self.blocked_macs.add(attacker_mac)
            return True 
        
        if attacker_mac in self.blocked_macs:
            return True
        
        self.logger.info(f"[DEFENSE] Firewall ile engelleniyor: {attacker_mac}")
        
        try:
            r1 = self._run(["sudo", "iptables", "-A", "INPUT", "-m", "mac",
                           "--mac-source", attacker_mac, "-j", "DROP"])
            
            if r1.returncode == 0:
                self.blocked_macs.add(attacker_mac)
                self.logger.info(f"[DEFENSE] ✓ {attacker_mac} iptables ile engellendi!")
                return True
            return False
        except Exception:
            return False
    
    def _unblock_mac(self, mac: str):
        """Varsa engeli kaldırır."""
        if self.system == "linux" and mac in self.blocked_macs:
            try:
                self._run(["sudo", "iptables", "-D", "INPUT", "-m", "mac",
                          "--mac-source", mac, "-j", "DROP"])
            except: pass
        self.blocked_macs.discard(mac)
    
    # === SAVUNMA 4: Ağ Kesme (Acil Durum Butonu) ===
    
    def disable_network(self) -> bool:
        """Çok yüksek tehdit durumunda interneti komple keser."""
        self.logger.critical("[DEFENSE] ⚠️ KRİTİK SEVİYE: AĞ BAĞLANTISI KESİLİYOR!")
        
        try:
            if self.system == "windows":
                result = self._run(["netsh", "interface", "set", "interface",
                                   self.interface, "disable"])
            elif self.system == "darwin": # macOS
                # macOS: sudo ifconfig en0 down
                result = self._run(["sudo", "ifconfig", self.interface, "down"])
            else: # Linux
                result = self._run(["sudo", "ip", "link", "set", self.interface, "down"])
            
            if result.returncode == 0:
                self.logger.critical("[DEFENSE] ✓ Ağ arayüzü kapatıldı.")
                return True
            return False
        except Exception:
            return False
    
    def auto_defend(self, detected_mac: str, severity: str = "medium"):
        """Şiddet seviyesine göre savunma uygular."""
        norm_attacker_mac = self._normalize_mac(detected_mac)
        
        self.logger.warning(f"[DEFENSE] Otomatik savunma başlatıldı (Seviye: {severity})")
        
        # 1. ADIM: ARP Tablosunu Kilitle (En Önemlisi)
        self.apply_static_arp()
        
        # 2. ADIM: Saldırganı Blokla (Sadece Linux'ta aktiftir)
        if severity in ["medium", "high", "critical"]:
            self.block_attacker_mac(norm_attacker_mac)
        
        # 3. ADIM: Kritik seviyede fişi çek
        if severity == "critical":
            self.disable_network()
    
    def cleanup(self):
        """Program kapanırken her şeyi temizle."""
        self.logger.info("[DEFENSE] Temizlik yapılıyor...")
        for mac in list(self.blocked_macs):
            self._unblock_mac(mac)
        self.remove_static_arp()