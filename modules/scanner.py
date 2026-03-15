import nmap

def scan(domain):
    scanner = nmap.PortScanner()
    
    results = {
        "domain": domain,
        "open_ports": [],
        "risky_ports": [],
        "risk_score": 0
    }

    risky = {
        21: "FTP - sends data in plaintext",
        23: "Telnet - sends data in plaintext",
        25: "SMTP - mail server exposed",
        80: "HTTP - no encryption",
        443: "HTTPS - standard, low risk",
        3306: "MySQL - database exposed",
        3389: "RDP - remote desktop exposed",
        8080: "HTTP alternate - no encryption"
    }

    try:
        scanner.scan(domain, "21-25,80,443,3306,3389,8080", "-T4 --open")
        
        for host in scanner.all_hosts():
            for proto in scanner[host].all_protocols():
                ports = scanner[host][proto].keys()
                for port in ports:
                    service = scanner[host][proto][port]
                    port_info = {
                        "port": port,
                        "state": service["state"],
                        "name": service["name"],
                        "version": service["version"]
                    }
                    results["open_ports"].append(port_info)

                    if port in risky:
                        results["risky_ports"].append({
                            "port": port,
                            "reason": risky[port]
                        })
                        if port not in [80, 443, 8080]:
                            results["risk_score"] += 20
                        elif port == 80:
                            results["risk_score"] += 10

    except Exception as e:
        results["error"] = str(e)

    return results