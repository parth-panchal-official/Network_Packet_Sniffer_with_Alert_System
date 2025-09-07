from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, Raw
import sqlite3, os
from email.mime.text import MIMEText
from datetime import datetime, timedelta
from collections import defaultdict, deque
from dotenv import load_dotenv
import smtplib

load_dotenv()

EMAIL_SENDER = os.getenv("EMAIL_SENDER")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
EMAIL_RECEIVER = os.getenv("EMAIL_RECEIVER")
SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))

packet_log = defaultdict(lambda: deque())
port_access_log = defaultdict(set)
alerted_ips = set()
CREDENTIAL_SNIFFING_ENABLED = True


def set_credential_sniffing(enabled):
    global CREDENTIAL_SNIFFING_ENABLED
    CREDENTIAL_SNIFFING_ENABLED = enabled


def send_email_alert(ip, reason):
    if ip in alerted_ips:
        return
    alerted_ips.add(ip)
    msg = MIMEText(f"Anomaly detected from IP: {ip}\nReason: {reason}")
    msg['Subject'] = "[ALERT] Network Anomaly Detected"
    msg['From'] = EMAIL_SENDER
    msg['To'] = EMAIL_RECEIVER
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.sendmail(EMAIL_SENDER, EMAIL_RECEIVER, msg.as_string())
    except Exception as e:
        print(f"Failed to send email: {e}")


def detect_anomaly(src_ip, dst_port):
    now = datetime.now()
    window_start = now - timedelta(seconds=10)
    packet_log[src_ip].append(now)
    port_access_log[src_ip].add(dst_port)
    while packet_log[src_ip] and packet_log[src_ip][0] < window_start:
        packet_log[src_ip].popleft()
    if len(port_access_log[src_ip]) > 10:
        send_email_alert(src_ip, "Possible Port Scanning")
    if len(packet_log[src_ip]) > 100:
        send_email_alert(src_ip, "Possible Flooding Attack")


def log_dns(pkt):
    if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
        timestamp = datetime.now().isoformat()
        src_ip = pkt[IP].src if pkt.haslayer(IP) else ""
        query = pkt[DNSQR].qname.decode(errors="ignore") if pkt.haslayer(DNSQR) else ""
        conn = sqlite3.connect('dns_logs.db')
        cur = conn.cursor()
        cur.execute("INSERT INTO dns_requests (timestamp, src_ip, query) VALUES (?, ?, ?)",
                    (timestamp, src_ip, query))
        conn.commit()
        conn.close()


def log_credentials(pkt):
    if not CREDENTIAL_SNIFFING_ENABLED:
        return
    if pkt.haslayer(Raw):
        try:
            payload = pkt[Raw].load.decode(errors="ignore")
            if any(k in payload.lower() for k in ["username", "user", "login", "password", "pass"]):
                timestamp = datetime.now().isoformat()
                src_ip = pkt[IP].src if pkt.haslayer(IP) else ""
                conn = sqlite3.connect("credentials.db")
                cur = conn.cursor()
                cur.execute("INSERT INTO credentials (timestamp, src_ip, data) VALUES (?, ?, ?)",
                            (timestamp, src_ip, payload))
                conn.commit()
                conn.close()
        except Exception as e:
            print(f"Credential log error: {e}")


def log_packet(pkt):
    if not pkt.haslayer(IP):
        return
    src = pkt[IP].src
    dst = pkt[IP].dst
    length = len(pkt)
    proto, sport, dport, flags = 'IP', None, None, ''
    if TCP in pkt:
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        flags = str(pkt[TCP].flags)
        proto = 'TCP'
    elif UDP in pkt:
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport
        proto = 'UDP'
    conn = sqlite3.connect('packet_logs.db')
    cur = conn.cursor()
    cur.execute("INSERT INTO packets VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (datetime.now().isoformat(), src, dst, sport, dport, proto, length, flags))
    conn.commit()
    conn.close()
    if dport:
        detect_anomaly(src, dport)
    log_dns(pkt)
    log_credentials(pkt)


def initialize_databases():
    with sqlite3.connect('packet_logs.db') as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS packets (
                timestamp TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT,
                length INTEGER,
                flags TEXT
            )
        """)
    with sqlite3.connect('dns_logs.db') as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS dns_requests (
                timestamp TEXT,
                src_ip TEXT,
                query TEXT
            )
        """)
    with sqlite3.connect('credentials.db') as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS credentials (
                timestamp TEXT,
                src_ip TEXT,
                data TEXT
            )
        """)


def start_sniffing():
    initialize_databases()
    sniff(prn=log_packet, store=False)


if __name__ == "__main__":
    start_sniffing()
