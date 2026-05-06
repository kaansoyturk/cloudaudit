from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, flash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from models import db, User, Scan
from reporter import generate_report
from modules.dns_analyzer import analyze_dns
from modules.ssl_analyzer import analyze_ssl
from modules.port_scanner import scan_ports
from modules.cloud_detector import detect_cloud
from modules.email_security import analyze_email_security
from modules.score_engine import calculate_score
from scheduler import start_scheduler, add_scheduled_scan, remove_scheduled_scan
import os

app = Flask(__name__)
app.config["SECRET_KEY"] = "cloudaudit-secret-key-2026"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///cloudaudit.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")

        if User.query.filter_by(email=email).first():
            flash("Bu email zaten kayıtlı!", "error")
            return redirect(url_for("register"))

        hashed_pw = bcrypt.generate_password_hash(password).decode("utf-8")
        user = User(username=username, email=email, password=hashed_pw)
        db.session.add(user)
        db.session.commit()
        login_user(user)
        return redirect(url_for("index"))

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        user = User.query.filter_by(email=email).first()

        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for("index"))
        else:
            flash("Email veya şifre hatalı!", "error")

    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))

@app.route("/history")
@login_required
def history():
    scans = Scan.query.filter_by(user_id=current_user.id).order_by(Scan.created_at.desc()).all()
    return render_template("history.html", scans=scans)

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

        scan_record = Scan(
            user_id=current_user.id if current_user.is_authenticated else None,
            domain=domain,
            score=score["total_score"],
            grade=score["grade"],
            level=score["level"],
            dns_score=score["scores"]["dns"],
            ssl_score=score["scores"]["ssl"],
            port_score=score["scores"]["ports"],
            cloud_score=score["scores"]["cloud"],
            email_score=score["scores"]["email"],
            issue_count=score["issue_count"]
        )
        db.session.add(scan_record)
        db.session.commit()

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

@app.route("/schedule", methods=["POST"])
@login_required
def schedule():
    data = request.get_json()
    domain = data.get("domain")
    interval = data.get("interval", 24)

    last_scan = Scan.query.filter_by(
        user_id=current_user.id,
        domain=domain
    ).order_by(Scan.created_at.desc()).first()

    last_score = last_scan.score if last_scan else 0
    add_scheduled_scan(app, domain, current_user.id, last_score, interval)

    return jsonify({"success": True, "message": f"{domain} için zamanlanmış tarama eklendi!"})

@app.route("/schedule/remove", methods=["POST"])
@login_required
def schedule_remove():
    data = request.get_json()
    domain = data.get("domain")
    remove_scheduled_scan(current_user.id, domain)
    return jsonify({"success": True, "message": f"{domain} için zamanlanmış tarama kaldırıldı!"})

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    start_scheduler()
    app.run(debug=True, port=5051)