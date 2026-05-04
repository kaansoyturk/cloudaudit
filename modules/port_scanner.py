import socket
import concurrent.futures

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    1433: "MSSQL",
    1521: "Oracle DB",
    2375: "Docker",
    3306: "MySQL",
    3389: "RDP",
    4444: "Metasploit",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    9200: "Elasticsearch",
    27017: "MongoDB",
}

DANGEROUS_PORTS = {23, 445, 1433, 2375, 3389, 4444, 5900, 6379, 9200, 27017}

def check_port(host, port, timeout=1):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return port, result == 0
    except:
        return port, False

def scan_ports(domain):
    results = {
        "domain": domain,
        "open_ports": [],
        "dangerous_ports": [],
        "issues": [],
        "score": 100
    }

    try:
        host = socket.gethostbyname(domain)
    except:
        results["issues"].append("Domain IP'ye çözümlenemedi")
        results["score"] = 0
        return results

    print(f"    Port taranıyor: {host}")

    # Paralel port tarama
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = {
            executor.submit(check_port, host, port): port
            for port in COMMON_PORTS.keys()
        }

        for future in concurrent.futures.as_completed(futures):
            port, is_open = future.result()
            if is_open:
                service = COMMON_PORTS.get(port, "Bilinmiyor")
                results["open_ports"].append({
                    "port": port,
                    "service": service,
                    "dangerous": port in DANGEROUS_PORTS
                })

                if port in DANGEROUS_PORTS:
                    results["dangerous_ports"].append(port)
                    results["issues"].append(
                        f"Tehlikeli port açık: {port} ({service})"
                    )
                    results["score"] -= 20

    # Açık port sayısına göre puan
    open_count = len(results["open_ports"])
    if open_count > 10:
        results["issues"].append(f"Çok fazla açık port: {open_count}")
        results["score"] -= 10

    # Portları sırala
    results["open_ports"].sort(key=lambda x: x["port"])
    results["score"] = max(0, results["score"])
    return results