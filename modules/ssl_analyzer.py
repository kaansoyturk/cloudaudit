import ssl
import socket
from datetime import datetime

def analyze_ssl(domain):
    results = {
        "domain": domain,
        "has_ssl": False,
        "issuer": None,
        "expiry_date": None,
        "days_until_expiry": None,
        "version": None,
        "cipher": None,
        "issues": [],
        "score": 100
    }

    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                results["has_ssl"] = True
                cert = ssock.getpeercert()
                cipher = ssock.cipher()

                # Sertifika bilgileri
                issuer = dict(x[0] for x in cert["issuer"])
                results["issuer"] = issuer.get("organizationName", "Bilinmiyor")

                # Son kullanma tarihi
                expiry = datetime.strptime(
                    cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
                )
                results["expiry_date"] = expiry.strftime("%d.%m.%Y")
                days_left = (expiry - datetime.utcnow()).days
                results["days_until_expiry"] = days_left

                # SSL versiyonu ve cipher
                results["version"] = cipher[1]
                results["cipher"] = cipher[0]

                # Sertifika süresi kontrolü
                if days_left < 0:
                    results["issues"].append("SSL sertifikası süresi dolmuş!")
                    results["score"] -= 50
                elif days_left < 30:
                    results["issues"].append(f"SSL sertifikası {days_left} gün içinde dolacak!")
                    results["score"] -= 20
                elif days_left < 90:
                    results["issues"].append(f"SSL sertifikası {days_left} gün içinde dolacak")
                    results["score"] -= 10

                # Eski SSL versiyonu kontrolü
                if cipher[1] in ["TLSv1", "TLSv1.1", "SSLv2", "SSLv3"]:
                    results["issues"].append(f"Eski SSL versiyonu: {cipher[1]}")
                    results["score"] -= 30

    except ssl.SSLCertVerificationError:
        results["has_ssl"] = True
        results["issues"].append("SSL sertifikası geçersiz!")
        results["score"] -= 40

    except ConnectionRefusedError:
        results["has_ssl"] = False
        results["issues"].append("HTTPS bağlantısı kurulamadı")
        results["score"] -= 50

    except Exception as e:
        results["has_ssl"] = False
        results["issues"].append(f"SSL analizi yapılamadı: {str(e)}")
        results["score"] -= 50

    results["score"] = max(0, results["score"])
    return results