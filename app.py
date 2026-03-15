from flask import Flask, render_template, request
from modules.scanner import scan
from modules.web_audit import audit
from modules.scorer import score

app = Flask(__name__)

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def run_scan():
    domain = request.form.get("domain", "").strip()

    if not domain:
        return render_template("index.html", error="Please enter a domain.")

    domain = domain.replace("https://", "").replace("http://", "").rstrip("/")

    scan_results = scan(domain)
    audit_results = audit(domain)
    score_results = score(scan_results, audit_results)

    return render_template(
        "report.html",
        domain=domain,
        scan=scan_results,
        audit=audit_results,
        score=score_results
    )

if __name__ == "__main__":
    app.run(debug=True)