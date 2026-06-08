#!/usr/bin/env python3
"""
generate-dataset.py — генератор синтетических DNS PCAP сценариев
Сценарии покрывают все аномалии из analyzer.rs
"""

import struct
import random
import string
import os

# ─── PCAP helpers ────────────────────────────────────────────────────────────

PCAP_GLOBAL_HEADER = struct.pack(
    "<IHHiIII",
    0xa1b2c3d4,  # magic
    2, 4,        # version
    0,           # thiszone
    0,           # sigfigs
    65535,       # snaplen
    1,           # network = Ethernet
)

def pcap_packet(ts_sec, ts_usec, data):
    return struct.pack("<IIII", ts_sec, ts_usec, len(data), len(data)) + data

def eth_ip_udp(src_ip, dst_ip, src_port, dst_port, payload):
    """Ethernet + IPv4 + UDP фрейм"""
    # Ethernet (dst MAC, src MAC, ethertype=0x0800)
    eth = b"\xff\xff\xff\xff\xff\xff" + b"\x00\x11\x22\x33\x44\x55" + b"\x08\x00"
    # UDP
    udp_len = 8 + len(payload)
    udp = struct.pack(">HHHH", src_port, dst_port, udp_len, 0) + payload
    # IPv4
    ip_len = 20 + len(udp)
    ip = struct.pack(">BBHHHBBH4s4s",
        0x45, 0,          # version+ihl, dscp
        ip_len,           # total length
        random.randint(0, 65535),  # identification
        0,                # flags+fragment
        64,               # TTL
        17,               # protocol = UDP
        0,                # checksum (не считаем)
        bytes(map(int, src_ip.split("."))),
        bytes(map(int, dst_ip.split(".")))
    )
    return eth + ip + udp

def eth_ip_tcp(src_ip, dst_ip, src_port, dst_port, payload):
    """Ethernet + IPv4 + TCP фрейм (с DNS length prefix)"""
    eth = b"\xff\xff\xff\xff\xff\xff" + b"\x00\x11\x22\x33\x44\x55" + b"\x08\x00"
    # DNS over TCP: 2-байтовый length prefix
    tcp_payload = struct.pack(">H", len(payload)) + payload
    # TCP (минимальный заголовок без options, data offset = 5)
    tcp = struct.pack(">HHIIBBHHH",
        src_port, dst_port,
        random.randint(0, 2**32 - 1),  # seq
        0,                              # ack
        0x50,                           # data offset = 5 (20 bytes), reserved
        0x18,                           # flags: PSH + ACK
        65535,                          # window
        0,                              # checksum
        0,                              # urgent
    ) + tcp_payload
    ip_len = 20 + len(tcp)
    ip = struct.pack(">BBHHHBBH4s4s",
        0x45, 0, ip_len,
        random.randint(0, 65535), 0,
        64, 6, 0,  # protocol = TCP
        bytes(map(int, src_ip.split("."))),
        bytes(map(int, dst_ip.split(".")))
    )
    return eth + ip + tcp

# ─── DNS message builder ─────────────────────────────────────────────────────

def dns_name(name):
    """Кодируем DNS имя (без компрессии)"""
    encoded = b""
    for label in name.split("."):
        encoded += bytes([len(label)]) + label.encode()
    return encoded + b"\x00"

def dns_query(txid, name, qtype=1, rd=True):
    """Строим DNS Query пакет"""
    flags = 0x0100 if rd else 0x0000  # QR=0, RD=1
    header = struct.pack(">HHHHHH", txid, flags, 1, 0, 0, 0)
    question = dns_name(name) + struct.pack(">HH", qtype, 1)  # qtype, qclass=IN
    return header + question

def dns_response(txid, name, qtype=1, rcode=0, answers=None, rd=True, ra=True, truncated=False):
    """Строим DNS Response пакет"""
    flags = 0x8000  # QR=1
    if rd:       flags |= 0x0100
    if ra:       flags |= 0x0080
    if truncated: flags |= 0x0200
    flags |= (rcode & 0x000F)

    ans_count = len(answers) if answers else 0
    header = struct.pack(">HHHHHH", txid, flags, 1, ans_count, 0, 0)
    question = dns_name(name) + struct.pack(">HH", qtype, 1)

    ans_bytes = b""
    if answers:
        for (rtype, ttl, rdata) in answers:
            ans_bytes += dns_name(name)
            ans_bytes += struct.pack(">HHIH", rtype, 1, ttl, len(rdata))
            ans_bytes += rdata

    return header + question + ans_bytes

def dns_response_nxdomain(txid, name):
    return dns_response(txid, name, rcode=3)

def dns_response_servfail(txid, name):
    return dns_response(txid, name, rcode=2)

def ip_rdata(ip_str):
    return bytes(map(int, ip_str.split(".")))

# ─── Сценарии ────────────────────────────────────────────────────────────────

CLIENT  = "192.168.1.100"
SERVER  = "8.8.8.8"
CLIENT2 = "192.168.1.101"

def scenario_clean(ts_base):
    """Нормальный DNS трафик — запросы и ответы"""
    pkts = []
    t = ts_base
    domains = ["example.com", "github.com", "google.com", "cloudflare.com"]

    for domain in domains:
        txid = random.randint(1, 65535)
        # Запрос
        q = dns_query(txid, domain)
        pkts.append(pcap_packet(t, 0, eth_ip_udp(CLIENT, SERVER, 54321, 53, q)))
        t += 1
        # Ответ с A-записью
        r = dns_response(txid, domain, answers=[(1, 300, ip_rdata("93.184.216.34"))])
        pkts.append(pcap_packet(t, 500000, eth_ip_udp(SERVER, CLIENT, 53, 54321, r)))
        t += 1

    return pkts

def scenario_nxdomain_flood(ts_base):
    """DGA — поток NXDOMAIN за короткое время"""
    pkts = []
    t = ts_base

    def rand_domain():
        length = random.randint(8, 16)
        host = "".join(random.choices(string.ascii_lowercase, k=length))
        return f"{host}.evil-dga.com"

    for i in range(30):
        txid = random.randint(1, 65535)
        domain = rand_domain()
        q = dns_query(txid, domain)
        pkts.append(pcap_packet(t, i * 10000, eth_ip_udp(CLIENT, SERVER, 54400 + i, 53, q)))
        # Ответ NXDOMAIN через 50ms
        r = dns_response_nxdomain(txid, domain)
        pkts.append(pcap_packet(t, i * 10000 + 50000, eth_ip_udp(SERVER, CLIENT, 53, 54400 + i, r)))
        # Новый пакет каждые ~300ms
        if i % 3 == 2:
            t += 1

    return pkts

def scenario_slow_nxdomain_probe(ts_base):
    """Медленная разведка субдоменов"""
    pkts = []
    t = ts_base
    subdomains = ["admin", "vpn", "mail", "dev", "api", "staging", "test", "internal"]

    for sub in subdomains:
        txid = random.randint(1, 65535)
        domain = f"{sub}.target-corp.com"
        q = dns_query(txid, domain)
        pkts.append(pcap_packet(t, 0, eth_ip_udp(CLIENT2, SERVER, 55000, 53, q)))
        t += 1
        r = dns_response_nxdomain(txid, domain)
        pkts.append(pcap_packet(t, 100000, eth_ip_udp(SERVER, CLIENT2, 53, 55000, r)))
        t += 4  # медленно — раз в ~5 секунд

    return pkts

def scenario_dns_tunneling(ts_base):
    """DNS tunneling — длинные поддомены и TXT/NULL запросы"""
    pkts = []
    t = ts_base

    def rand_label(n):
        return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))

    # Длинные поддомены (exfiltration через A-запросы)
    for i in range(8):
        txid = random.randint(1, 65535)
        # Имитируем base32-encoded данные в поддомене
        chunk = rand_label(40)
        domain = f"{chunk}.tunnel.attacker.com"
        q = dns_query(txid, domain, qtype=1)
        pkts.append(pcap_packet(t, i * 200000, eth_ip_udp(CLIENT, SERVER, 56000 + i, 53, q)))
        r = dns_response(txid, domain, answers=[(1, 1, ip_rdata("1.2.3.4"))])
        pkts.append(pcap_packet(t, i * 200000 + 100000, eth_ip_udp(SERVER, CLIENT, 53, 56000 + i, r)))
        t += 1

    # TXT запросы (C2 commands)
    for i in range(5):
        txid = random.randint(1, 65535)
        chunk = rand_label(30)
        domain = f"{chunk}.c2.attacker.com"
        q = dns_query(txid, domain, qtype=16)  # TXT
        pkts.append(pcap_packet(t, i * 300000, eth_ip_udp(CLIENT, SERVER, 57000 + i, 53, q)))
        t += 1

    return pkts

def scenario_query_timeout(ts_base):
    """Запросы без ответов — сервер недоступен"""
    pkts = []
    t = ts_base
    domains = ["one.example.com", "two.example.com", "three.example.com",
               "four.example.com", "five.example.com"]

    for i, domain in enumerate(domains):
        txid = random.randint(1, 65535)
        q = dns_query(txid, domain)
        pkts.append(pcap_packet(t, i * 100000, eth_ip_udp(CLIENT, "10.0.0.1", 58000 + i, 53, q)))
        t += 1
        # Ретрансмиты
        for j in range(3):
            pkts.append(pcap_packet(t, j * 200000, eth_ip_udp(CLIENT, "10.0.0.1", 58000 + i, 53, q)))
        t += 5  # timeout

    return pkts

def scenario_fast_flux(ts_base):
    """Fast-flux — разные TTL для одного домена"""
    pkts = []
    t = ts_base
    domain = "flux.botnet.com"
    ttls = [30, 600, 5, 3600, 10]  # разброс 720x

    for i, ttl in enumerate(ttls):
        txid = random.randint(1, 65535)
        q = dns_query(txid, domain)
        pkts.append(pcap_packet(t, 0, eth_ip_udp(CLIENT, SERVER, 59000 + i, 53, q)))
        t += 1
        ip = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        r = dns_response(txid, domain, answers=[(1, ttl, ip_rdata(ip))])
        pkts.append(pcap_packet(t, 100000, eth_ip_udp(SERVER, CLIENT, 53, 59000 + i, r)))
        t += 2

    return pkts

def scenario_truncated_tcp(ts_base):
    """TC bit set — ответ обрезан, повтор по TCP"""
    pkts = []
    t = ts_base
    domain = "large-response.example.com"
    txid = random.randint(1, 65535)

    # Запрос по UDP
    q = dns_query(txid, domain, qtype=255)  # ANY
    pkts.append(pcap_packet(t, 0, eth_ip_udp(CLIENT, SERVER, 60000, 53, q)))
    t += 1

    # Truncated ответ
    r = dns_response(txid, domain, truncated=True)
    pkts.append(pcap_packet(t, 100000, eth_ip_udp(SERVER, CLIENT, 53, 60000, r)))
    t += 1

    # Повтор по TCP
    q_tcp = dns_query(txid + 1, domain, qtype=255)
    pkts.append(pcap_packet(t, 0, eth_ip_tcp(CLIENT, SERVER, 60001, 53, q_tcp)))
    t += 1
    r_tcp = dns_response(txid + 1, domain,
        answers=[(1, 300, ip_rdata("93.184.216.34"))] * 5)
    pkts.append(pcap_packet(t, 100000, eth_ip_tcp(SERVER, CLIENT, 53, 60001, r_tcp)))

    return pkts

def scenario_unsolicited(ts_base):
    """Ответ без запроса — возможный спуфинг"""
    pkts = []
    t = ts_base

    # Сначала нормальный запрос
    txid = random.randint(1, 65535)
    q = dns_query(txid, "bank.example.com")
    pkts.append(pcap_packet(t, 0, eth_ip_udp(CLIENT, SERVER, 61000, 53, q)))
    t += 1

    # Легитимный ответ
    r = dns_response(txid, "bank.example.com", answers=[(1, 300, ip_rdata("1.2.3.4"))])
    pkts.append(pcap_packet(t, 50000, eth_ip_udp(SERVER, CLIENT, 53, 61000, r)))
    t += 1

    # Второй ответ от другого IP (спуфинг)
    r2 = dns_response(txid, "bank.example.com", answers=[(1, 300, ip_rdata("10.10.10.10"))])
    pkts.append(pcap_packet(t, 60000, eth_ip_udp("5.5.5.5", CLIENT, 53, 61000, r2)))

    return pkts

# ─── Запись файлов ────────────────────────────────────────────────────────────

def write_pcap(filename, packets):
    os.makedirs("dataset", exist_ok=True)
    path = os.path.join("dataset", filename)
    with open(path, "wb") as f:
        f.write(PCAP_GLOBAL_HEADER)
        for pkt in packets:
            f.write(pkt)
    print(f"  wrote {path} ({len(packets)} packets)")

def main():
    print("Generating DNS PCAP datasets...")

    write_pcap("clean.pcap",          scenario_clean(1_700_000_000))
    write_pcap("nxdomain_flood.pcap", scenario_nxdomain_flood(1_700_001_000))
    write_pcap("slow_probe.pcap",     scenario_slow_nxdomain_probe(1_700_002_000))
    write_pcap("tunneling.pcap",      scenario_dns_tunneling(1_700_003_000))
    write_pcap("timeout.pcap",        scenario_query_timeout(1_700_004_000))
    write_pcap("fast_flux.pcap",      scenario_fast_flux(1_700_005_000))
    write_pcap("truncated_tcp.pcap",  scenario_truncated_tcp(1_700_006_000))
    write_pcap("unsolicited.pcap",    scenario_unsolicited(1_700_007_000))

    print("Done.")

if __name__ == "__main__":
    main()
