import requests

def audit(domain):
    results = {
        "domain": domain,
        "https": False,
        "headers": [],
        "cookies": [],
        "risk_score": 0
    }

    security_headers = {
        "Content-Security-Policy": "Prevents XSS attacks",
        "Strict-Transport-Security": "Forces HTTPS connections",
        "X-Frame-Options": "Prevents clickjacking",
        "X-Content-Type-Options": "Prevents MIME sniffing",
        "Referrer-Policy": "Controls referrer information",
        "Permissions-Policy": "Controls browser features"
    }

    try:
        url = f"https://{domain}"
        response = requests.get(url, timeout=10, allow_redirects=True)
        results["https"] = True

    except:
        try:
            url = f"http://{domain}"
            response = requests.get(url, timeout=10, allow_redirects=True)
            results["https"] = False
            results["risk_score"] += 20
        except Exception as e:
            results["error"] = str(e)
            return results

    for header, description in security_headers.items():
        present = header in response.headers
        results["headers"].append({
            "name": header,
            "present": present,
            "description": description,
            "value": response.headers.get(header, "Not set")
        })
        if not present:
            results["risk_score"] += 10

    for cookie in response.cookies:
        cookie_info = {
            "name": cookie.name,
            "secure": cookie.secure,
            "httponly": cookie.has_nonstandard_attr("HttpOnly"),
            "samesite": cookie.has_nonstandard_attr("SameSite")
        }
        results["cookies"].append(cookie_info)
        if not cookie.secure:
            results["risk_score"] += 10
        if not cookie.has_nonstandard_attr("HttpOnly"):
            results["risk_score"] += 5

    return results