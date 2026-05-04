# ☁️ CloudAudit — Bulut Güvenlik Analiz Platformu

Domain ve IP adreslerinin güvenlik parmak izini çıkaran, kapsamlı güvenlik analizi yapan web platformu.

## Ne Yapıyor?

Bir domain gir, CloudAudit 5 farklı modülde analiz yaparak 0-100 arası güvenlik skoru üretir.

## Modüller

- DNS Analizi — A, MX, NS, TXT kayıtları, SPF, DMARC, DNSSEC kontrolü
- SSL Analizi — Sertifika geçerliliği, şifreleme gücü, son kullanma tarihi
- Port Tarama — 23 kritik port, tehlikeli port tespiti
- Cloud Tespiti — AWS, GCP, Azure, Cloudflare tespiti, güvenlik header analizi
- Email Güvenliği — SPF, DKIM, DMARC politika analizi

## Teknolojiler

- Python 3
- Flask — Web arayüzü
- dnspython — DNS sorguları
- cryptography — SSL analizi
- requests — HTTP header analizi
- reportlab — PDF rapor

## Kurulum

    git clone https://github.com/kaansoyturk/cloudaudit.git
    cd cloudaudit
    python3 -m venv venv
    source venv/bin/activate
    pip3 install flask requests dnspython cryptography reportlab colorama

## Kullanim

    python3 app.py

Tarayicide ac: http://localhost:5051

## Ornek Cikti

- github.com — 86/100 A Guvenli
- Tespit edilen sorunlar: DNSSEC pasif, Permissions-Policy eksik
- Cloud provider: AWS, CDN: Cloudflare

## Gelistirici

Kaan Soyturk — github.com/kaansoyturk