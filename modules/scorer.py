def score(scan_results, audit_results, ssl_results=None):
    total_risk = 0

    total_risk += scan_results.get("risk_score", 0)
    total_risk += audit_results.get("risk_score", 0)
    
    if ssl_results:
        total_risk += ssl_results.get("risk_score", 0)

    if total_risk == 0:
        grade = "A"
        summary = "Excellent. No major issues found."
        color = "green"
    elif total_risk <= 20:
        grade = "B"
        summary = "Good. A few minor issues to look into."
        color = "lightgreen"
    elif total_risk <= 40:
        grade = "C"
        summary = "Fair. Some security issues need attention."
        color = "orange"
    elif total_risk <= 70:
        grade = "D"
        summary = "Poor. Several serious security issues found."
        color = "orangered"
    else:
        grade = "F"
        summary = "Critical. Major security vulnerabilities detected."
        color = "red"

    return {
        "grade": grade,
        "total_risk": total_risk,
        "summary": summary,
        "color": color
    }