import ssl
import socket
from datetime import datetime

def check_ssl(domain):
    results = {
        "domain": domain,
        "valid": False,
        "issuer": "Unknown",
        "expires": "Unknown",
        "days_left": 0,
        "self_signed": False,
        "expired": False,
        "risk_score": 0
    }

    try:
        context = ssl.create_default_context()
        conn = context.wrap_socket(
            socket.socket(socket.AF_INET),
            server_hostname=domain
        )
        conn.settimeout(10)
        conn.connect((domain, 443))
        cert = conn.getpeercert()
        conn.close()

        results["valid"] = True

        issuer = dict(x[0] for x in cert["issuer"])
        subject = dict(x[0] for x in cert["subject"])
        results["issuer"] = issuer.get("organizationName", "Unknown")

        expire_date = datetime.strptime(
            cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
        )
        results["expires"] = expire_date.strftime("%d %b %Y")
        days_left = (expire_date - datetime.utcnow()).days
        results["days_left"] = days_left

        if days_left < 0:
            results["expired"] = True
            results["risk_score"] += 40
        elif days_left < 30:
            results["risk_score"] += 20

        issuer_name = issuer.get("organizationName", "")
        subject_name = subject.get("organizationName", "")
        issuer_cn = issuer.get("commonName", "")
        
        if issuer_name == subject_name and "CA" not in issuer_cn and "Root" not in issuer_cn:
            results["self_signed"] = True
            results["risk_score"] += 30

    except ssl.SSLCertVerificationError:
        results["risk_score"] += 40
        results["valid"] = False
    except Exception as e:
        results["error"] = str(e)

    return results