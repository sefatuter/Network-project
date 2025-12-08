import subprocess
import sys
import time
import re
import platform
import logging
import argparse
import context
from logger import DetectionLogger

# Defense modülünü import et
try:
    from defense import ARPDefender
    DEFENSE_AVAILABLE = True
except ImportError:
    DEFENSE_AVAILABLE = False
    print("[!] defense.py bulunamadı. Savunma özellikleri devre dışı.")

parser: argparse.ArgumentParser

# Defense için ek değişkenler
defender = None
defense_enabled = False
defense_mode = "active"
attack_count = 0

def get_gateway_ip():
    """
    Return the system's default gateway IP as a string.
    Uses 'netstat' or 'ip route' to be language independent.
    """
    system = platform.system()
    
    if system == "Windows":
        # 'route print' is better than ipconfig because it uses standard 0.0.0.0 notation
        # regardless of system language (English vs Turkish).
        cmd = ["route", "print", "0.0.0.0"]
        try:
            output = subprocess.check_output(cmd).decode(errors="ignore")
            # Look for the line starting with 0.0.0.0
            # Example: 0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.35     25
            for line in output.splitlines():
                if line.strip().startswith("0.0.0.0"):
                    parts = line.split()
                    if len(parts) > 2:
                        # The 3rd column is usually the Gateway in 'route print'
                        context.gateway_ip = parts[2]
                        return
        except Exception as e:
            context.mitm_logger.error(f"[-] Gateway IP tespiti hatasi: {e}")
            
    else:
        # Linux / macOS
        try:
            cmd = ["ip", "route"]
            output = subprocess.check_output(cmd).decode()
            match = re.search(r"default via (\S+)", output)
            if match:
                context.gateway_ip = match.group(1)
                return
        except Exception:
            pass
            
    context.gateway_ip = None 

def get_mac_from_arp(target_ip):
    """
    Returns MAC address of a specific IP from the OS ARP table.
    Refactored to take IP as an argument explicitly.
    """
    cmd = ["arp", "-a"]
    try:
        output = subprocess.check_output(cmd).decode(errors="ignore")
    except subprocess.CalledProcessError:
        return None

    # Regex to find MAC address
    # Supports: 00:11:22... and 00-11-22...
    mac_regex = r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}"

    for line in output.splitlines():
        # Check if the line contains our target IP
        if target_ip in line:
            mac_match = re.search(mac_regex, line)
            if mac_match:
                # Normalize MAC to standard format (e.g. replace - with :)
                return mac_match.group(0).replace("-", ":").lower()
                
    return None

def determine_severity(count):
    """Ardışık saldırı sayısına göre şiddet seviyesi belirler."""
    if count <= 2:
        return "low"
    elif count <= 5:
        return "medium"
    elif count <= 10:
        return "high"
    else:
        return "critical"

def print_status():
    """Başlangıç durum bilgisini yazdırır."""
    global defense_enabled, defense_mode
    
    print("\n" + "="*60)
    print("🛡️  ARP SPOOFING TESPİT VE SAVUNMA SİSTEMİ")
    print("="*60)
    print(f"  Gateway IP      : {context.gateway_ip}")
    print(f"  Orijinal MAC    : {context.original_mac}")
    print(f"  İzleme Aralığı  : {context.interval} saniye")
    print(f"  Savunma Durumu  : {'✓ AKTİF' if defense_enabled else '✗ DEVRE DIŞI'}")
    if defense_enabled:
        print(f"  Savunma Modu    : {defense_mode.upper()}")
    print("="*60)
    if defense_enabled:
        print("  SAVUNMA MODLARI:")
        print("    passive    - Sadece uyarı verir")
        print("    active     - ARP tablosunu düzeltir")
        print("    aggressive - Tam savunma (engelleme + ağ kapatma)")
        print("="*60)
    print("  Çıkmak için CTRL+C")
    print("="*60 + "\n")

def monitor_gateway():
    """Sürekli olarak Gateway MAC adresini izler."""
    global defender, defense_enabled, defense_mode, attack_count
    
    # 1. Gateway IP'yi bul
    get_gateway_ip()
    if not context.gateway_ip:
        context.mitm_logger.error("[-] Gateway IP bulunamadı (Dil sorunu veya ağ hatası).")
        return
    
    context.mitm_logger.info(f"[+] İzlenen Gateway IP: {context.gateway_ip}")

    # 2. İlk (Orijinal) MAC adresini öğren
    initial_mac = get_mac_from_arp(context.gateway_ip)
    
    # Eğer ilk başta bulamazsa bir kez ping atıp tekrar denesin
    if not initial_mac:
        context.mitm_logger.info("[*] Gateway ARP tablosunda yok, ping atılıyor...")
        subprocess.call(["ping", "-n" if platform.system() == "Windows" else "-c", "1", context.gateway_ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(2)
        initial_mac = get_mac_from_arp(context.gateway_ip)

    if initial_mac:
        context.original_mac = initial_mac
        context.mitm_logger.info(f"[+] Orijinal Gateway MAC: {context.original_mac}")
    else:
        context.mitm_logger.error("[-] Gateway MAC adresi tespit edilemedi. Çıkılıyor.")
        return

    # 3. Defense modülünü başlat (eğer aktifse)
    if defense_enabled and DEFENSE_AVAILABLE:
        defender = ARPDefender(
            gateway_ip=context.gateway_ip,
            original_mac=context.original_mac,
            logger=context.mitm_logger
        )
        context.mitm_logger.info(f"[DEFENSE] Savunma modülü aktif (Mod: {defense_mode})")
        
        # Agresif modda başlangıçta statik ARP ekle
        if defense_mode == "aggressive":
            defender.apply_static_arp()

    # last_mac'i başlangıç değerine eşitle
    last_mac = context.original_mac
    attack_count = 0

    # Durum bilgisini yazdır
    print_status()
    
    context.mitm_logger.info(f"[*] İzleme Başladı...")
    
    while True:
        try:
            time.sleep(context.interval)
            
            # --- AKTİF KONTROL (PING) ---
            # ARP tablosunu taze tutmak için
            param = "-n" if platform.system().lower() == "windows" else "-c"
            subprocess.call(["ping", param, "1", context.gateway_ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # Tabloyu oku
            current_mac = get_mac_from_arp(context.gateway_ip)

            if not current_mac:
                # MAC okunamazsa (ping başarısız vs) atla
                continue

            # =====================================================================
            # SALDIRI TESPİT EDİLDİ
            # =====================================================================
            if current_mac != context.original_mac:
                attack_count += 1
                severity = determine_severity(attack_count)
                
                context.mitm_logger.critical("!!!" + "="*50 + "!!!")
                context.mitm_logger.critical(f"⚠️  UYARI: ARP SPOOFING TESPİT EDİLDİ! (#{attack_count})")
                context.mitm_logger.critical(f"   Şiddet Seviyesi: {severity.upper()}")
                context.mitm_logger.critical(f"   Beklenen MAC : {context.original_mac}")
                context.mitm_logger.critical(f"   Görülen MAC  : {current_mac}") 
                context.mitm_logger.critical("!!!" + "="*50 + "!!!")
                
                # =====================================================
                # SAVUNMA UYGULA (eğer aktifse)
                # =====================================================
                if defense_enabled and defender:
                    context.mitm_logger.info("[DEFENSE] 🛡️ Savunma mekanizması devreye giriyor...")
                    
                    if defense_mode == "passive":
                        # Pasif mod: Sadece uyar
                        context.mitm_logger.info("[DEFENSE] Pasif mod - Sadece uyarı verildi.")
                        
                    elif defense_mode == "active":
                        # Aktif mod: ARP tablosunu düzelt
                        context.mitm_logger.info("[DEFENSE] Aktif mod - ARP tablosu düzeltiliyor...")
                        defender.restore_arp_table()
                        
                    elif defense_mode == "aggressive":
                        # Agresif mod: Tam savunma
                        context.mitm_logger.info("[DEFENSE] Agresif mod - Tam savunma uygulanıyor...")
                        defender.auto_defend(current_mac, severity)
                
                # Saldırı yeni başladıysa bildir
                if last_mac == context.original_mac:
                    context.mitm_logger.warning("[!] Yeni saldırı başladı!")
            
            # =====================================================================
            # SALDIRI SONA ERDİ
            # =====================================================================
            elif current_mac == context.original_mac and last_mac != context.original_mac:
                context.mitm_logger.info("="*50)
                context.mitm_logger.info("[+] ✓ ARP Spoofing sona erdi. MAC normale döndü.")
                context.mitm_logger.info(f"[+] Toplam ardışık saldırı tespiti: {attack_count}")
                context.mitm_logger.info("="*50)
                attack_count = 0  # Sayacı sıfırla

            last_mac = current_mac

        except KeyboardInterrupt:
            break
        except Exception as e:
            context.mitm_logger.error(f"Döngü hatası: {e}")

def setup_arg_parser():
    global parser
    parser = argparse.ArgumentParser(
        description="ARP Spoofing Tespit ve Savunma Sistemi",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Örnekler:
  sudo python3 detect.py -c                         # Sadece tespit
  sudo python3 detect.py -c -d                      # Tespit + Savunma (active mod)
  sudo python3 detect.py -c -d --defense-mode aggressive  # Agresif savunma
  sudo python3 detect.py -c -f -d                   # Konsol + Dosya + Savunma
  sudo python3 detect.py -c -i 3                    # 3 saniye aralıkla izle
        """
    )
    
    # İzleme aralığı
    parser.add_argument("-i", "--interval", type=int, default=5, help="Interval in seconds (default: 5)")
    
    # Konsol çıktısı
    parser.add_argument('-c','--console', dest='console', action='store_true', help='Enable console output')
    parser.add_argument('-noc','--no-console', dest='console', action='store_false', help='Disable console output')
    parser.set_defaults(console=True)
    
    # Dosya çıktısı
    parser.add_argument('-f','--file', dest='file', action='store_true', help='Enable file output')
    parser.add_argument('-nof','--no-file', dest='file', action='store_false', help='Disable file output')
    parser.set_defaults(file=False)
    
    # Savunma argümanları
    parser.add_argument('-d', '--defense', dest='defense', action='store_true', 
                        help='Enable defense module (requires defense.py)')
    parser.add_argument('-nod', '--no-defense', dest='defense', action='store_false', 
                        help='Disable defense module')
    parser.set_defaults(defense=False)
    
    parser.add_argument('--defense-mode', type=str, choices=['passive', 'active', 'aggressive'],
                        default='active', help='Defense mode: passive, active, aggressive (default: active)')

def parse_args():
    global defense_enabled, defense_mode
    
    args = parser.parse_args()
    context.interval = args.interval
    context.active_handlers = []
    
    if args.console:
        context.active_handlers.append("console")
    if args.file:
        context.active_handlers.append("file")
    
    # Defense ayarları
    defense_enabled = args.defense
    defense_mode = args.defense_mode
    
    # Defense modülü yoksa uyar
    if defense_enabled and not DEFENSE_AVAILABLE:
        print("[!] UYARI: defense.py bulunamadı! Savunma devre dışı bırakıldı.")
        print("[!] defense.py dosyasını detect.py ile aynı dizine koyun.")
        defense_enabled = False

def cleanup():
    """Program kapanırken temizlik yapar."""
    global defender
    if defender:
        context.mitm_logger.info("\n[*] Program kapatılıyor...")
        defender.cleanup()

def main():
    setup_arg_parser()
    parse_args()
    context.mitm_logger = DetectionLogger.setup_logger()
    
    try:
        monitor_gateway()
    finally:
        cleanup()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] CTRL+C tespit edildi. Çıkılıyor...")
        cleanup()
        sys.exit(0)
