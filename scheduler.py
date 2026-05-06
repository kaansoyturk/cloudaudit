from apscheduler.schedulers.background import BackgroundScheduler
from datetime import datetime
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

scheduler = BackgroundScheduler()

def send_notification(email, domain, old_score, new_score, grade):
    try:
        GMAIL_USER = "kaannsoyturk@gmail.com"
        GMAIL_APP_PASSWORD = "bjaoaugmzbyfrilv"

        msg = MIMEMultipart()
        msg["From"] = GMAIL_USER
        msg["To"] = email
        msg["Subject"] = f"CloudAudit — {domain} güvenlik skoru değişti!"

        diff = new_score - old_score
        emoji = "📈" if diff > 0 else "📉"

        body = f"""
CloudAudit Otomatik Tarama Raporu

Domain  : {domain}
Tarih   : {datetime.now().strftime('%d.%m.%Y %H:%M')}

Eski Skor : {old_score}
Yeni Skor : {new_score}
Değişim   : {emoji} {'+' if diff > 0 else ''}{diff} puan
Seviye    : {grade}

Detaylı rapor için: http://localhost:5051
        """

        msg.attach(MIMEText(body, "plain"))
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(GMAIL_USER, GMAIL_APP_PASSWORD)
        server.sendmail(GMAIL_USER, email, msg.as_string())
        server.quit()
        print(f"📧 Bildirim gönderildi: {email}")

    except Exception as e:
        print(f"❌ Mail gönderilemedi: {e}")

def run_scheduled_scan(app, domain, user_id, last_score):
    with app.app_context():
        from modules.dns_analyzer import analyze_dns
        from modules.ssl_analyzer import analyze_ssl
        from modules.port_scanner import scan_ports
        from modules.cloud_detector import detect_cloud
        from modules.email_security import analyze_email_security
        from modules.score_engine import calculate_score
        from models import db, Scan, User

        print(f"⏰ Zamanlanmış tarama: {domain}")

        try:
            dns_results = analyze_dns(domain)
            ssl_results = analyze_ssl(domain)
            port_results = scan_ports(domain)
            cloud_results = detect_cloud(domain)
            email_results = analyze_email_security(domain)
            score = calculate_score(dns_results, ssl_results, port_results, cloud_results, email_results)

            # Veritabanına kaydet
            scan_record = Scan(
                user_id=user_id,
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

            # Skor değiştiyse bildir
            if abs(score["total_score"] - last_score) >= 5:
                user = User.query.get(user_id)
                if user:
                    send_notification(
                        user.email, domain,
                        last_score, score["total_score"],
                        score["grade"]
                    )

            print(f"✅ Zamanlanmış tarama tamamlandı: {domain} — {score['total_score']}")

        except Exception as e:
            print(f"❌ Zamanlanmış tarama hatası: {e}")

def start_scheduler():
    if not scheduler.running:
        scheduler.start()
        print("⏰ Scheduler başlatıldı")

def add_scheduled_scan(app, domain, user_id, last_score, interval_hours=24):
    job_id = f"scan_{user_id}_{domain}"

    # Varsa kaldır
    if scheduler.get_job(job_id):
        scheduler.remove_job(job_id)

    scheduler.add_job(
        run_scheduled_scan,
        "interval",
        hours=interval_hours,
        args=[app, domain, user_id, last_score],
        id=job_id
    )
    print(f"⏰ Zamanlanmış tarama eklendi: {domain} — her {interval_hours} saatte bir")

def remove_scheduled_scan(user_id, domain):
    job_id = f"scan_{user_id}_{domain}"
    if scheduler.get_job(job_id):
        scheduler.remove_job(job_id)
        print(f"⏰ Zamanlanmış tarama kaldırıldı: {domain}")