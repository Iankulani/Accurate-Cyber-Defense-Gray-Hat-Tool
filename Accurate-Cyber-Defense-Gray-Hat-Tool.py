#!/usr/bin/env python3
import os
import sys
import time
import socket
import threading
import subprocess
import platform
import json
import datetime
import scapy.all as scapy
from collections import deque
import psutil
import requests
import readline
import logging
from logging.handlers import RotatingFileHandler
import signal
import argparse
from typing import List, Dict, Optional, Tuple, Deque

# Constants
VERSION = "25.0.0"
AUTHOR = "Ian Carter Kulani"
MAX_HISTORY = 100
CONFIG_FILE = "cybermon_config.json"
LOG_FILE = "cybermon.log"
MAX_LOG_SIZE = 10 * 1024 * 1024  # 10MB
BACKUP_COUNT = 5

# ANSI color codes
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
PURPLE = "\033[95m"
CYAN = "\033[96m"
WHITE = "\033[97m"
BOLD = "\033[1m"
RESET = "\033[0m"
UNDERLINE = "\033[4m"

# Global variables
monitoring_active = False
monitored_ips = set()
command_history = deque(maxlen=MAX_HISTORY)
telegram_config = {"token": "", "chat_id": ""}
alerts = []
stats = {
    "ddos_detected": 0,
    "dos_detected": 0,
    "port_scan_detected": 0,
    "udp_flood_detected": 0,
    "https_flood_detected": 0,
    "total_packets": 0,
    "malicious_packets": 0
}
packet_buffer = deque(maxlen=1000)
monitoring_thread = None
exit_event = threading.Event()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        RotatingFileHandler(LOG_FILE, maxBytes=MAX_LOG_SIZE, backupCount=BACKUP_COUNT),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("CyberMon")

class CyberSecurityMonitor:
    def __init__(self):
        self.load_config()
        self.setup_signal_handlers()
        self.running = True
        self.last_alert_time = {}
        self.alert_thresholds = {
            "ddos": {"count": 100, "window": 10},
            "dos": {"count": 50, "window": 5},
            "port_scan": {"count": 20, "window": 30},
            "udp_flood": {"count": 200, "window": 10},
            "https_flood": {"count": 100, "window": 10}
        }
        self.port_scan_tracker = {}
        self.https_request_tracker = {}
        self.packet_counts = {}

    def setup_signal_handlers(self):
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

    def signal_handler(self, signum, frame):
        logger.info(f"Received signal {signum}, shutting down...")
        self.running = False
        exit_event.set()
        if monitoring_thread and monitoring_thread.is_alive():
            monitoring_thread.join(2)
        sys.exit(0)

    def load_config(self):
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, "r") as f:
                    config = json.load(f)
                    global monitored_ips, telegram_config
                    monitored_ips = set(config.get("monitored_ips", []))
                    telegram_config = config.get("telegram_config", telegram_config)
                    logger.info("Configuration loaded successfully")
        except Exception as e:
            logger.error(f"Error loading config: {e}")

    def save_config(self):
        try:
            config = {
                "monitored_ips": list(monitored_ips),
                "telegram_config": telegram_config
            }
            with open(CONFIG_FILE, "w") as f:
                json.dump(config, f, indent=4)
            logger.info("Configuration saved successfully")
        except Exception as e:
            logger.error(f"Error saving config: {e}")

    def send_telegram_alert(self, message: str):
        if not telegram_config.get("token") or not telegram_config.get("chat_id"):
            logger.warning("Telegram not configured. Cannot send alerts.")
            return False

        url = f"https://api.telegram.org/bot{telegram_config['token']}/sendMessage"
        payload = {
            "chat_id": telegram_config["chat_id"],
            "text": message,
            "parse_mode": "HTML"
        }

        try:
            response = requests.post(url, json=payload, timeout=10)
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Error sending Telegram alert: {e}")
            return False

    def test_telegram(self):
        if not telegram_config.get("token") or not telegram_config.get("chat_id"):
            print(f"{RED}Telegram not configured. Use 'config telegram token' and 'config telegram chat_id' first.{RESET}")
            return

        message = "🚨 CyberMon Test Alert 🚨\nThis is a test message from your Cyber Security Monitoring Tool."
        if self.send_telegram_alert(message):
            print(f"{GREEN}Test message sent successfully to Telegram.{RESET}")
        else:
            print(f"{RED}Failed to send test message to Telegram.{RESET}")

    def packet_handler(self, packet):
        if not self.running:
            return

        stats["total_packets"] += 1
        packet_buffer.append((time.time(), packet))
        
        try:
            if packet.haslayer(scapy.IP):
                src_ip = packet[scapy.IP].src
                dst_ip = packet[scapy.IP].dst
                
                if src_ip not in self.packet_counts:
                    self.packet_counts[src_ip] = {"count": 0, "timestamps": []}
                self.packet_counts[src_ip]["count"] += 1
                self.packet_counts[src_ip]["timestamps"].append(time.time())
                
                if dst_ip in monitored_ips:
                    self.check_ddos_attack(dst_ip)
                
                self.check_dos_attack(src_ip)
                
                if packet.haslayer(scapy.TCP):
                    self.check_port_scan(packet)
                
                if packet.haslayer(scapy.UDP):
                    self.check_udp_flood(packet)
                
                if packet.haslayer(scapy.TCP) and packet.haslayer(scapy.Raw):
                    self.check_https_flood(packet)
                    
        except Exception as e:
            logger.error(f"Error processing packet: {e}")

    def check_ddos_attack(self, target_ip: str):
        current_time = time.time()
        window_start = current_time - self.alert_thresholds["ddos"]["window"]
        
        sources = set()
        for timestamp, packet in packet_buffer:
            if timestamp >= window_start and packet.haslayer(scapy.IP) and packet[scapy.IP].dst == target_ip:
                sources.add(packet[scapy.IP].src)
        
        if len(sources) >= self.alert_thresholds["ddos"]["count"]:
            last_alert = self.last_alert_time.get("ddos", 0)
            if current_time - last_alert > 60:
                message = f"🚨 DDoS attack detected on {target_ip} from {len(sources)} sources!"
                alerts.append(message)
                logger.warning(message)
                self.send_telegram_alert(message)
                stats["ddos_detected"] += 1
                stats["malicious_packets"] += len(sources)
                self.last_alert_time["ddos"] = current_time

    def check_dos_attack(self, src_ip: str):
        current_time = time.time()
        window_start = current_time - self.alert_thresholds["dos"]["window"]
        
        timestamps = [ts for ts in self.packet_counts[src_ip]["timestamps"] if ts >= window_start]
        packet_count = len(timestamps)
        
        if packet_count >= self.alert_thresholds["dos"]["count"]:
            last_alert = self.last_alert_time.get(f"dos_{src_ip}", 0)
            if current_time - last_alert > 60:
                message = f"🚨 DoS attack detected from {src_ip} ({packet_count} packets in {self.alert_thresholds['dos']['window']}s)"
                alerts.append(message)
                logger.warning(message)
                self.send_telegram_alert(message)
                stats["dos_detected"] += 1
                stats["malicious_packets"] += packet_count
                self.last_alert_time[f"dos_{src_ip}"] = current_time

    def check_port_scan(self, packet):
        src_ip = packet[scapy.IP].src
        dst_port = packet[scapy.TCP].dport
        
        if src_ip not in self.port_scan_tracker:
            self.port_scan_tracker[src_ip] = {"ports": set(), "timestamps": []}
        
        self.port_scan_tracker[src_ip]["ports"].add(dst_port)
        self.port_scan_tracker[src_ip]["timestamps"].append(time.time())
        
        current_time = time.time()
        window_start = current_time - self.alert_thresholds["port_scan"]["window"]
        
        timestamps = [ts for ts in self.port_scan_tracker[src_ip]["timestamps"] if ts >= window_start]
        unique_ports = len(self.port_scan_tracker[src_ip]["ports"])
        
        if len(timestamps) >= self.alert_thresholds["port_scan"]["count"]:
            last_alert = self.last_alert_time.get(f"port_scan_{src_ip}", 0)
            if current_time - last_alert > 60:
                message = f"🚨 Port scan detected from {src_ip} ({unique_ports} unique ports scanned)"
                alerts.append(message)
                logger.warning(message)
                self.send_telegram_alert(message)
                stats["port_scan_detected"] += 1
                stats["malicious_packets"] += len(timestamps)
                self.last_alert_time[f"port_scan_{src_ip}"] = current_time

    def check_udp_flood(self, packet):
        src_ip = packet[scapy.IP].src
        current_time = time.time()
        window_start = current_time - self.alert_thresholds["udp_flood"]["window"]
        
        udp_count = 0
        for timestamp, pkt in packet_buffer:
            if (timestamp >= window_start and pkt.haslayer(scapy.IP) and pkt.haslayer(scapy.UDP) and 
                pkt[scapy.IP].src == src_ip):
                udp_count += 1
        
        if udp_count >= self.alert_thresholds["udp_flood"]["count"]:
            last_alert = self.last_alert_time.get(f"udp_flood_{src_ip}", 0)
            if current_time - last_alert > 60:
                message = f"🚨 UDP flood detected from {src_ip} ({udp_count} UDP packets in {self.alert_thresholds['udp_flood']['window']}s)"
                alerts.append(message)
                logger.warning(message)
                self.send_telegram_alert(message)
                stats["udp_flood_detected"] += 1
                stats["malicious_packets"] += udp_count
                self.last_alert_time[f"udp_flood_{src_ip}"] = current_time

    def check_https_flood(self, packet):
        try:
            raw_data = packet[scapy.Raw].load.decode('utf-8', errors='ignore').lower()
            if "http" in raw_data or "https" in raw_data:
                src_ip = packet[scapy.IP].src
                current_time = time.time()
                
                if src_ip not in self.https_request_tracker:
                    self.https_request_tracker[src_ip] = {"count": 0, "timestamps": []}
                
                self.https_request_tracker[src_ip]["count"] += 1
                self.https_request_tracker[src_ip]["timestamps"].append(current_time)
                
                window_start = current_time - self.alert_thresholds["https_flood"]["window"]
                
                timestamps = [ts for ts in self.https_request_tracker[src_ip]["timestamps"] if ts >= window_start]
                request_count = len(timestamps)
                
                if request_count >= self.alert_thresholds["https_flood"]["count"]:
                    last_alert = self.last_alert_time.get(f"https_flood_{src_ip}", 0)
                    if current_time - last_alert > 60:
                        message = f"🚨 HTTP/S flood detected from {src_ip} ({request_count} requests in {self.alert_thresholds['https_flood']['window']}s)"
                        alerts.append(message)
                        logger.warning(message)
                        self.send_telegram_alert(message)
                        stats["https_flood_detected"] += 1
                        stats["malicious_packets"] += request_count
                        self.last_alert_time[f"https_flood_{src_ip}"] = current_time
        except:
            pass

    def start_monitoring(self, interface: str = None):
        global monitoring_active, monitoring_thread
        
        if monitoring_active:
            print(f"{YELLOW}Monitoring is already active.{RESET}")
            return
        
        if not monitored_ips:
            print(f"{RED}No IPs to monitor. Use 'add ip' first.{RESET}")
            return
        
        monitoring_active = True
        exit_event.clear()
        
        def monitor_network():
            logger.info(f"Starting network monitoring on interface {interface or 'default'}")
            print(f"{GREEN}Starting network monitoring...{RESET}")
            
            try:
                scapy.sniff(iface=interface, prn=self.packet_handler, store=False, stop_filter=lambda x: exit_event.is_set())
            except Exception as e:
                logger.error(f"Error in monitoring thread: {e}")
            finally:
                global monitoring_active
                monitoring_active = False
                logger.info("Network monitoring stopped")
        
        monitoring_thread = threading.Thread(target=monitor_network, daemon=True)
        monitoring_thread.start()

    def stop_monitoring(self):
        global monitoring_active
        
        if not monitoring_active:
            print(f"{YELLOW}Monitoring is not active.{RESET}")
            return
        
        exit_event.set()
        monitoring_active = False
        
        if monitoring_thread and monitoring_thread.is_alive():
            monitoring_thread.join(2)
        
        print(f"{GREEN}Monitoring stopped.{RESET}")
        logger.info("Monitoring stopped by user")

    def get_network_interfaces(self) -> List[str]:
        try:
            return scapy.get_if_list()
        except Exception as e:
            logger.error(f"Error getting network interfaces: {e}")
            return []

def print_banner():
    banner = f"""
{CYAN}{BOLD}
   ___    _____  _____  __  __  _____  _____  ______  _____  
 / _ \  / ____||_   _||  \/  ||_   _|/ ____||  ____||  __ \ 
/ /_\ \| |       | |  | \  / |  | | | (___  | |__   | |__) |
   _  || |       | |  | |\/| |  | |  \___ \ |  __|  |  _  / 
  | | || |____  _| |_ | |  | | _| |_ ____) || |____ | | \ \ 
\_| |_/ \_____||_____||_|  |_||_____|_____/ |______||_|  \_\
                                                             
                                                             
{WHITE}{BOLD}            Cyber Defense Monitoring Tool v1.0{RESET}
{WHITE}{BOLD}            Created by {AUTHOR}{RESET}
{WHITE}{BOLD}            {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RESET}"""
    print(banner)

def print_help():
    help_text = f"""
{WHITE}{BOLD}{UNDERLINE}Available Commands:{RESET}

{GREEN}General Commands:{RESET}
  {WHITE}help{RESET}              - Show this help message
  {WHITE}clear{RESET}             - Clear the screen
  {WHITE}exit{RESET}              - Exit the program

{GREEN}Monitoring Commands:{RESET}
  {WHITE}start monitoring [iface]{RESET} - Start monitoring network traffic
  {WHITE}stop{RESET}              - Stop monitoring
  {WHITE}status{RESET}            - Show monitoring status and statistics
  {WHITE}view{RESET}              - View alerts and monitored IPs
  {WHITE}add ip <IP>{RESET}       - Add an IP to monitor
  {WHITE}remove ip <IP>{RESET}    - Remove an IP from monitoring

{GREEN}Network Diagnostic Commands:{RESET}
  {WHITE}ping ip <IP>{RESET}      - Ping an IP address
  {WHITE}traceroute ip <IP>{RESET} - Perform a traceroute to an IP
  {WHITE}udptraceroute ip <IP>{RESET} - UDP traceroute
  {WHITE}tcptraceroute ip <IP>{RESET} - TCP traceroute
  {WHITE}scan ip <IP>{RESET}      - Scan common ports on an IP
  {WHITE}netstat{RESET}           - Show network connections and ports
  {WHITE}sniff ip <IP>{RESET}     - Capture packets from specific IP
  {WHITE}analyze pcap <file>{RESET} - Analyze pcap file

{GREEN}Telegram Integration:{RESET}
  {WHITE}test telegram{RESET}     - Test Telegram alert functionality
  {WHITE}config telegram token <TOKEN>{RESET} - Set Telegram bot token
  {WHITE}config telegram chat_id <ID>{RESET} - Set Telegram chat ID
  {WHITE}export data{RESET}       - Export data and alerts to Telegram

{GREEN}History & Data:{RESET}
  {WHITE}history{RESET}           - Display command history
  {WHITE}export data{RESET}       - Export data and alerts to Telegram
"""
    print(help_text)

def execute_command(cmd: str, monitor: CyberSecurityMonitor):
    command_history.append(cmd)
    parts = cmd.split()
    
    if not parts:
        return
    
    try:
        if parts[0] == "help":
            print_help()
            
        elif parts[0] == "ping" and len(parts) >= 3 and parts[1] == "ip":
            ip = parts[2]
            ping_ip(ip)
            
        elif parts[0] == "traceroute" and len(parts) >= 3 and parts[1] == "ip":
            ip = parts[2]
            traceroute_ip(ip)
            
        elif parts[0] == "udptraceroute" and len(parts) >= 3 and parts[1] == "ip":
            ip = parts[2]
            udp_traceroute(ip)
            
        elif parts[0] == "tcptraceroute" and len(parts) >= 3 and parts[1] == "ip":
            ip = parts[2]
            tcp_traceroute(ip)
            
        elif parts[0] == "view":
            view_data(monitor)
            
        elif parts[0] == "status":
            show_status(monitor)
            
        elif parts[0] == "history":
            show_history()
            
        elif parts[0] == "export" and len(parts) >= 2 and parts[1] == "data":
            export_data(monitor)
            
        elif parts[0] == "test" and len(parts) >= 2 and parts[1] == "telegram":
            monitor.test_telegram()
            
        elif parts[0] == "config" and len(parts) >= 4 and parts[1] == "telegram":
            if parts[2] == "token":
                telegram_config["token"] = parts[3]
                monitor.save_config()
                print(f"{GREEN}Telegram token updated.{RESET}")
            elif parts[2] == "chat_id":
                telegram_config["chat_id"] = parts[3]
                monitor.save_config()
                print(f"{GREEN}Telegram chat ID updated.{RESET}")
            else:
                print(f"{RED}Invalid Telegram config option. Use 'token' or 'chat_id'.{RESET}")
                
        elif parts[0] == "start" and len(parts) >= 2 and parts[1] == "monitoring":
            iface = parts[2] if len(parts) >= 3 else None
            monitor.start_monitoring(iface)
            
        elif parts[0] == "stop":
            monitor.stop_monitoring()
            
        elif parts[0] == "scan" and len(parts) >= 3 and parts[1] == "ip":
            ip = parts[2]
            scan_ip(ip)
            
        elif parts[0] == "netstat":
            show_netstat()
            
        elif parts[0] == "add" and len(parts) >= 3 and parts[1] == "ip":
            ip = parts[2]
            add_ip(ip, monitor)
            
        elif parts[0] == "remove" and len(parts) >= 3 and parts[1] == "ip":
            ip = parts[2]
            remove_ip(ip, monitor)
            
        elif parts[0] == "sniff" and len(parts) >= 3 and parts[1] == "ip":
            ip = parts[2]
            sniff_ip(ip)
            
        elif parts[0] == "analyze" and len(parts) >= 3 and parts[1] == "pcap":
            pcap_file = parts[2]
            analyze_pcap(pcap_file, monitor)
            
        elif parts[0] == "clear":
            os.system("cls" if platform.system() == "Windows" else "clear")
            
        elif parts[0] == "exit":
            monitor.stop_monitoring()
            monitor.save_config()
            print(f"{GREEN}Exiting... Goodbye!{RESET}")
            sys.exit(0)
            
        else:
            print(f"{RED}Unknown command: {cmd}{RESET}")
            print(f"{WHITE}Type 'help' for available commands.{RESET}")
            
    except Exception as e:
        logger.error(f"Error executing command '{cmd}': {e}")
        print(f"{RED}Error executing command: {e}{RESET}")

def ping_ip(ip: str):
    try:
        param = "-n" if platform.system().lower() == "windows" else "-c"
        command = ["ping", param, "4", ip]
        print(f"{WHITE}Pinging {ip}...{RESET}")
        subprocess.run(command, check=True)
    except subprocess.CalledProcessError:
        print(f"{RED}Failed to ping {ip}{RESET}")
    except Exception as e:
        print(f"{RED}Error pinging IP: {e}{RESET}")

def traceroute_ip(ip: str):
    try:
        command = ["traceroute", ip] if platform.system().lower() != "windows" else ["tracert", ip]
        print(f"{WHITE}Traceroute to {ip}...{RESET}")
        subprocess.run(command, check=True)
    except subprocess.CalledProcessError:
        print(f"{RED}Failed to traceroute {ip}{RESET}")
    except Exception as e:
        print(f"{RED}Error performing traceroute: {e}{RESET}")

def udp_traceroute(ip: str):
    try:
        if platform.system().lower() == "windows":
            print(f"{RED}UDP traceroute not supported on Windows. Using standard traceroute.{RESET}")
            traceroute_ip(ip)
            return
            
        command = ["traceroute", "-U", ip]
        print(f"{WHITE}UDP Traceroute to {ip}...{RESET}")
        subprocess.run(command, check=True)
    except subprocess.CalledProcessError:
        print(f"{RED}Failed to UDP traceroute {ip}{RESET}")
    except Exception as e:
        print(f"{RED}Error performing UDP traceroute: {e}{RESET}")

def tcp_traceroute(ip: str):
    try:
        if platform.system().lower() == "windows":
            print(f"{RED}TCP traceroute not supported on Windows. Using standard traceroute.{RESET}")
            traceroute_ip(ip)
            return
            
        command = ["traceroute", "-T", ip]
        print(f"{WHITE}TCP Traceroute to {ip}...{RESET}")
        subprocess.run(command, check=True)
    except subprocess.CalledProcessError:
        print(f"{RED}Failed to TCP traceroute {ip}{RESET}")
    except Exception as e:
        print(f"{RED}Error performing TCP traceroute: {e}{RESET}")

def view_data(monitor: CyberSecurityMonitor):
    print(f"\n{WHITE}{BOLD}{UNDERLINE}Alerts:{RESET}")
    if not alerts:
        print(f"{WHITE}No alerts detected.{RESET}")
    else:
        for alert in alerts[-10:]:
            print(f"{RED}• {alert}{RESET}")
    
    print(f"\n{WHITE}{BOLD}{UNDERLINE}Monitored IPs:{RESET}")
    if not monitored_ips:
        print(f"{WHITE}No IPs being monitored.{RESET}")
    else:
        for ip in monitored_ips:
            print(f"{WHITE}• {ip}{RESET}")
    
    print(f"\n{WHITE}{BOLD}{UNDERLINE}Available Network Interfaces:{RESET}")
    interfaces = monitor.get_network_interfaces()
    if not interfaces:
        print(f"{WHITE}No network interfaces found.{RESET}")
    else:
        for iface in interfaces:
            print(f"{WHITE}• {iface}{RESET}")

def show_status(monitor: CyberSecurityMonitor):
    print(f"\n{WHITE}{BOLD}{UNDERLINE}Monitoring Status:{RESET}")
    status = "ACTIVE" if monitoring_active else "INACTIVE"
    color = GREEN if monitoring_active else RED
    print(f"{WHITE}Monitoring: {color}{status}{RESET}")
    
    print(f"\n{WHITE}{BOLD}{UNDERLINE}Statistics:{RESET}")
    print(f"{WHITE}• Total packets analyzed: {stats['total_packets']}{RESET}")
    print(f"{WHITE}• Malicious packets detected: {stats['malicious_packets']}{RESET}")
    print(f"{RED}• DDoS attacks detected: {stats['ddos_detected']}{RESET}")
    print(f"{RED}• DoS attacks detected: {stats['dos_detected']}{RESET}")
    print(f"{RED}• Port scans detected: {stats['port_scan_detected']}{RESET}")
    print(f"{RED}• UDP floods detected: {stats['udp_flood_detected']}{RESET}")
    print(f"{RED}• HTTP/S floods detected: {stats['https_flood_detected']}{RESET}")
    
    print(f"\n{WHITE}{BOLD}{UNDERLINE}Telegram Status:{RESET}")
    if telegram_config.get("token") and telegram_config.get("chat_id"):
        print(f"{WHITE}Telegram notifications: {GREEN}ENABLED{RESET}")
    else:
        print(f"{WHITE}Telegram notifications: {RED}DISABLED{RESET}")

def show_history():
    print(f"\n{WHITE}{BOLD}{UNDERLINE}Command History:{RESET}")
    if not command_history:
        print(f"{WHITE}No commands in history.{RESET}")
    else:
        for i, cmd in enumerate(command_history, 1):
            print(f"{WHITE}{i}. {cmd}{RESET}")

def export_data(monitor: CyberSecurityMonitor):
    if not telegram_config.get("token") or not telegram_config.get("chat_id"):
        print(f"{RED}Telegram not configured. Use 'config telegram token' and 'config telegram chat_id' first.{RESET}")
        return
    
    message = "📊 CyberMon Data Export 📊\n\n"
    message += f"🔄 Monitoring Status: {'ACTIVE' if monitoring_active else 'INACTIVE'}\n"
    message += f"📡 Monitored IPs: {len(monitored_ips)}\n\n"
    
    message += "📈 Statistics:\n"
    message += f"• Total packets analyzed: {stats['total_packets']}\n"
    message += f"• Malicious packets detected: {stats['malicious_packets']}\n"
    message += f"• DDoS attacks detected: {stats['ddos_detected']}\n"
    message += f"• DoS attacks detected: {stats['dos_detected']}\n"
    message += f"• Port scans detected: {stats['port_scan_detected']}\n"
    message += f"• UDP floods detected: {stats['udp_flood_detected']}\n"
    message += f"• HTTP/S floods detected: {stats['https_flood_detected']}\n\n"
    
    message += "🚨 Recent Alerts:\n"
    if not alerts:
        message += "No alerts detected.\n"
    else:
        for alert in alerts[-5:]:
            message += f"• {alert}\n"
    
    if monitor.send_telegram_alert(message):
        print(f"{GREEN}Data exported to Telegram successfully.{RESET}")
    else:
        print(f"{RED}Failed to export data to Telegram.{RESET}")

def scan_ip(ip: str):
    common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 8080]
    print(f"{WHITE}Scanning common ports on {ip}...{RESET}")
    
    open_ports = []
    
    def scan_port(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
        except:
            pass
    
    threads = []
    for port in common_ports:
        t = threading.Thread(target=scan_port, args=(port,))
        threads.append(t)
        t.start()
    
    for t in threads:
        t.join()
    
    if open_ports:
        print(f"{GREEN}Open ports found:{RESET}")
        for port in open_ports:
            try:
                service = socket.getservbyport(port)
                print(f"{WHITE}• Port {port} ({service}){RESET}")
            except:
                print(f"{WHITE}• Port {port} (unknown service){RESET}")
    else:
        print(f"{WHITE}No open ports found on common ports.{RESET}")

def show_netstat():
    print(f"\n{WHITE}{BOLD}{UNDERLINE}Network Connections:{RESET}")
    try:
        connections = psutil.net_connections()
        print(f"{WHITE}Proto{'Local Address':>25}{'Remote Address':>25}{'Status':>15}{'PID':>10}{RESET}")
        
        for conn in connections:
            if conn.status == psutil.CONN_LISTEN:
                color = GREEN
            elif conn.status == psutil.CONN_ESTABLISHED:
                color = WHITE
            else:
                color = RED
            
            laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
            raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else ""
            
            print(f"{color}{conn.type:<6}{laddr:>25}{raddr:>25}{conn.status:>15}{conn.pid:>10}{RESET}")
    except Exception as e:
        print(f"{RED}Error getting network connections: {e}{RESET}")

def add_ip(ip: str, monitor: CyberSecurityMonitor):
    try:
        socket.inet_aton(ip)
        if ip in monitored_ips:
            print(f"{YELLOW}IP {ip} is already being monitored.{RESET}")
        else:
            monitored_ips.add(ip)
            monitor.save_config()
            print(f"{GREEN}Added IP {ip} to monitoring list.{RESET}")
    except socket.error:
        print(f"{RED}Invalid IP address: {ip}{RESET}")

def remove_ip(ip: str, monitor: CyberSecurityMonitor):
    if ip in monitored_ips:
        monitored_ips.remove(ip)
        monitor.save_config()
        print(f"{GREEN}Removed IP {ip} from monitoring list.{RESET}")
    else:
        print(f"{YELLOW}IP {ip} is not being monitored.{RESET}")

def sniff_ip(ip: str):
    print(f"{WHITE}Starting packet capture for IP {ip}... (Press Ctrl+C to stop){RESET}")
    try:
        def packet_handler(pkt):
            if pkt.haslayer(scapy.IP):
                if pkt[scapy.IP].src == ip or pkt[scapy.IP].dst == ip:
                    print(f"{WHITE}{pkt.summary()}{RESET}")
        
        scapy.sniff(filter=f"host {ip}", prn=packet_handler, store=False)
    except KeyboardInterrupt:
        print(f"\n{GREEN}Packet capture stopped.{RESET}")
    except Exception as e:
        print(f"{RED}Error during packet capture: {e}{RESET}")

def analyze_pcap(pcap_file: str, monitor: CyberSecurityMonitor):
    print(f"{WHITE}Analyzing pcap file: {pcap_file}{RESET}")
    try:
        packets = scapy.rdpcap(pcap_file)
        print(f"{GREEN}Loaded {len(packets)} packets from {pcap_file}{RESET}")
        
        for pkt in packets:
            monitor.packet_handler(pkt)
        
        print(f"{GREEN}Analysis complete. Check the alerts and status.{RESET}")
    except Exception as e:
        print(f"{RED}Error analyzing pcap file: {e}{RESET}")

def main():
    print_banner()
    monitor = CyberSecurityMonitor()
    
    # Set up command line interface
    readline.parse_and_bind("tab: complete")
    readline.set_history_length(MAX_HISTORY)
    
    while True:
        try:
            prompt = f"{CYAN}CyberMon{RESET} {BLUE}➜{RESET} "
            cmd = input(prompt).strip()
            if cmd:
                execute_command(cmd, monitor)
        except KeyboardInterrupt:
            print("\nUse 'exit' to quit or 'help' for commands.")
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            print(f"{RED}An error occurred: {e}{RESET}")

if __name__ == "__main__":
    # Check for root/admin privileges
    if platform.system() == "Windows":
        try:
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                print(f"{RED}Error: This tool requires administrator privileges on Windows.{RESET}")
                sys.exit(1)
        except:
            pass
    else:
        if os.geteuid() != 0:
            print(f"{RED}Error: This tool requires root privileges on Unix systems.{RESET}")
            sys.exit(1)
    
    main()