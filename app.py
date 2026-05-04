from flask import Flask, render_template, request, jsonify, send_file
from reporter import generate_report
from modules.dns_analyzer import analyze_dns
from modules.ssl_analyzer import analyze_ssl
from modules.port_scanner import scan_ports
from modules.cloud_detector import detect_cloud
from modules.email_security import analyze_email_security
from modules.score_engine import calculate_score
import os

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json()
    domain = data.get("domain", "").strip()

    domain = domain.replace("https://", "").replace("http://", "").replace("www.", "")
    if "/" in domain:
        domain = domain.split("/")[0]

    if not domain:
        return jsonify({"error": "Domain giriniz!"}), 400

    print(f"\n🔍 Taranıyor: {domain}")

    try:
        print("  [1/5] DNS analizi...")
        dns_results = analyze_dns(domain)

        print("  [2/5] SSL analizi...")
        ssl_results = analyze_ssl(domain)

        print("  [3/5] Port tarama...")
        port_results = scan_ports(domain)

        print("  [4/5] Cloud tespiti...")
        cloud_results = detect_cloud(domain)

        print("  [5/5] Email güvenliği...")
        email_results = analyze_email_security(domain)

        print("  Skor hesaplanıyor...")
        score = calculate_score(
            dns_results, ssl_results,
            port_results, cloud_results, email_results
        )

        return jsonify({
            "domain": domain,
            "score": score,
            "dns": dns_results,
            "ssl": ssl_results,
            "ports": port_results,
            "cloud": cloud_results,
            "email": email_results
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/report", methods=["POST"])
def report():
    data = request.get_json()
    domain = data.get("domain")
    scan_data = data.get("scan_data")

    if not domain or not scan_data:
        return jsonify({"error": "Eksik veri!"}), 400

    os.makedirs("reports", exist_ok=True)
    output_path = f"reports/{domain}_report.pdf"
    generate_report(domain, scan_data, output_path)

    return send_file(
        output_path,
        as_attachment=True,
        download_name=f"cloudaudit_{domain}.pdf"
    )

if __name__ == "__main__":
    app.run(debug=True, port=5051)