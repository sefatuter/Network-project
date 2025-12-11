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
    Sistemin varsayılan ağ geçidini bulur.
    Gereksiz boşlukları temizler (strip).
    """
    system = platform.system()
    gateway = None
    
    try:
        if system == "Windows":
            cmd = ["route", "print", "0.0.0.0"]
            output = subprocess.check_output(cmd).decode(errors="ignore")
            for line in output.splitlines():
                if line.strip().startswith("0.0.0.0"):
                    parts = line.split()
                    if len(parts) > 2:
                        gateway = parts[2]
                        break 
                        
        elif system == "Darwin":  # macOS
            cmd = ["route", "-n", "get", "default"]
            output = subprocess.check_output(cmd).decode()
            match = re.search(r'gateway:\s+(\S+)', output)
            if match:
                gateway = match.group(1)

        else:  # Linux
            cmd = ["ip", "route"]
            output = subprocess.check_output(cmd).decode()
            match = re.search(r"default via (\S+)", output)
            if match:
                gateway = match.group(1)

    except Exception as e:
        pass

    if gateway:
        context.gateway_ip = gateway.strip()
    else:
        context.gateway_ip = None

def get_mac_from_arp():
    """
    İşletim sistemi ARP tablosundan Gateway MAC adresini çeker.
    macOS sıfır kısaltması (0 vs 00) ve parantezli yapı için güncellendi.
    """
    if not context.gateway_ip:
        return None

    cmd = ["arp", "-a"]
    try:
        output = subprocess.check_output(cmd).decode(errors="ignore")
    except subprocess.CalledProcessError:
        return None

    # Regex: 1 veya 2 hane kabul eder (macOS uyumu)
    mac_regex = r"([0-9a-fA-F]{1,2}[:-]){5}[0-9a-fA-F]{1,2}"

    for line in output.splitlines():
        if context.gateway_ip in line:
            mac_match = re.search(mac_regex, line)
            
            if mac_match:
                raw_mac = mac_match.group(0)
                # Ayraçları standartlaştır
                raw_mac = raw_mac.replace("-", ":").lower()
                
                # macOS'in kısalttığı (0) gibi yerleri (00) formatına tamamla
                parts = raw_mac.split(":")
                normalized_mac = ":".join([p.zfill(2) for p in parts])
                
                return normalized_mac
                
    return None

def determine_severity(count):
    """Ardışık saldırı sayısına göre şiddet seviyesi belirler."""
    if count > 2 and count <= 5:
        return "medium"
    elif count <= 10:
        return "high"
    else:
        return "critical"

def print_status():
    """Başlangıç durum bilgisini yazdırır."""
    global defense_enabled, defense_mode

    lines = []
    lines.append("\n" + "="*60)
    lines.append("🛡️  ARP SPOOFING TESPİT VE SAVUNMA SİSTEMİ")
    lines.append("="*60)
    lines.append(f"  Gateway IP      : {context.gateway_ip}")
    lines.append(f"  Orijinal MAC    : {context.original_mac}")
    lines.append(f"  İzleme Aralığı  : {context.interval} saniye")
    lines.append(f"  Savunma Durumu  : {'✓ AKTİF' if defense_enabled else '✗ DEVRE DIŞI'}")
    if defense_enabled:
        lines.append(f"  Savunma Modu    : {defense_mode.upper()}")
    lines.append("="*60)
    if defense_enabled:
        lines.append("  SAVUNMA MODLARI:")
        lines.append("    passive    - Sadece uyarı verir")
        lines.append("    active     - ARP tablosunu düzeltir")
        lines.append("    aggressive - Tam savunma (engelleme + ağ kapatma)")
        lines.append("="*60)
    lines.append("  Çıkmak için CTRL+C")
    lines.append("="*60 + "\n")

    if context.mitm_logger:
        for l in lines:
            context.mitm_logger.info(l)
    else:
        for l in lines:
            print(l)

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
    initial_mac = get_mac_from_arp()
    
    if not initial_mac:
        context.mitm_logger.info("[*] Gateway ARP tablosunda yok, ping atılıyor...")
        param = "-n" if platform.system().lower() == "windows" else "-c"
        subprocess.call(["ping", param, "1", context.gateway_ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(2)
        initial_mac = get_mac_from_arp()

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

    last_mac = context.original_mac
    attack_count = 0

    print_status()
    
    context.mitm_logger.info(f"[*] İzleme Başladı...")
    
    while True:
        try:
            time.sleep(context.interval)
            
            # --- AKTİF KONTROL (PING) ---
            param = "-n" if platform.system().lower() == "windows" else "-c"
            subprocess.call(["ping", param, "1", context.gateway_ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # Tabloyu oku
            current_mac = get_mac_from_arp()

            if not current_mac:
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
                # SAVUNMA UYGULA
                # =====================================================
                if defense_enabled and defender:
                    context.mitm_logger.info("[DEFENSE] 🛡️ Savunma mekanizması devreye giriyor...")
                    
                    if defense_mode == "passive":
                        context.mitm_logger.info("[DEFENSE] Pasif mod - Sadece uyarı verildi.")
                        
                    elif defense_mode == "active":
                        context.mitm_logger.info("[DEFENSE] Aktif mod - ARP tablosu düzeltiliyor...")
                        defender.apply_static_arp()
                        
                    elif defense_mode == "aggressive":
                        context.mitm_logger.info("[DEFENSE] Agresif mod - Tam savunma uygulanıyor...")
                        defender.auto_defend(current_mac, severity)
                
                if last_mac == context.original_mac:
                    context.mitm_logger.warning("[!] Yeni saldırı başladı!")
            
            # =====================================================================
            # SALDIRI SONA ERDİ
            # =====================================================================
            elif last_mac != context.original_mac:
                context.mitm_logger.info("="*50)
                context.mitm_logger.info("[+] ✓ ARP Spoofing sona erdi. MAC normale döndü.")
                context.mitm_logger.info(f"[+] Toplam ardışık saldırı tespiti: {attack_count}")
                context.mitm_logger.info("="*50)
                attack_count = 0 

            last_mac = current_mac

        except KeyboardInterrupt:
            break
        except Exception as e:
            context.mitm_logger.error(f"Döngü hatası: {e}")

def setup_arg_parser():
    global parser
    parser = argparse.ArgumentParser(
        description="ARP Spoofing Tespit ve Savunma Sistemi",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # İzleme aralığı (Float destekler)
    parser.add_argument("-i", "--interval", type=float, default=5, help="Interval in seconds (default: 5)")
    
    parser.add_argument('-c','--console', dest='console', action='store_true', help='Enable console output')
    parser.add_argument('-noc','--no-console', dest='console', action='store_false', help='Disable console output')
    parser.set_defaults(console=True)
    
    parser.add_argument('-f','--file', dest='file', action='store_true', help='Enable file output')
    parser.add_argument('-nof','--no-file', dest='file', action='store_false', help='Disable file output')
    parser.set_defaults(file=False)
    
    parser.add_argument('-d', '--defense', dest='defense', action='store_true', help='Enable defense module')
    parser.add_argument('-nod', '--no-defense', dest='defense', action='store_false', help='Disable defense module')
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
    
    defense_enabled = args.defense
    defense_mode = args.defense_mode
    
    if defense_enabled and not DEFENSE_AVAILABLE:
        print("[!] UYARI: defense.py bulunamadı! Savunma devre dışı bırakıldı.")
        defense_enabled = False

def cleanup():
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
        sys.exit(0)