import socket
import requests

# Bilinen bulut IP aralıkları ve özellikleri
CLOUD_PROVIDERS = {
    "AWS": [
        "amazonaws.com", "aws.amazon.com", "cloudfront.net",
        "elasticloadbalancing", "s3.amazonaws.com"
    ],
    "Google Cloud": [
        "googleapis.com", "googlecloud.com", "appspot.com",
        "cloudfunctions.net", "run.app"
    ],
    "Azure": [
        "azure.com", "azurewebsites.net", "cloudapp.azure.com",
        "azurefd.net", "blob.core.windows.net"
    ],
    "Cloudflare": [
        "cloudflare.com", "cloudflare-dns.com"
    ],
    "Vercel": [
        "vercel.app", "vercel.com", "now.sh"
    ],
    "Netlify": [
        "netlify.app", "netlify.com"
    ],
    "Heroku": [
        "herokuapp.com", "heroku.com"
    ],
    "DigitalOcean": [
        "digitalocean.com", "ondigitalocean.app"
    ]
}

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Content-Security-Policy",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy"
]

def detect_cloud(domain):
    results = {
        "domain": domain,
        "ip": None,
        "cloud_provider": None,
        "cdn": None,
        "server": None,
        "security_headers": {},
        "missing_headers": [],
        "technologies": [],
        "issues": [],
        "score": 100
    }

    # IP tespiti
    try:
        ip = socket.gethostbyname(domain)
        results["ip"] = ip
    except:
        results["issues"].append("IP adresi tespit edilemedi")
        results["score"] -= 10

    # HTTP headers analizi
    try:
        response = requests.get(
            f"https://{domain}",
            timeout=10,
            allow_redirects=True,
            headers={"User-Agent": "CloudAudit Security Scanner 1.0"}
        )

        headers = response.headers

        # Server bilgisi
        if "Server" in headers:
            results["server"] = headers["Server"]
            results["technologies"].append(headers["Server"])

        # X-Powered-By
        if "X-Powered-By" in headers:
            results["technologies"].append(headers["X-Powered-By"])

        # CDN tespiti
        if "CF-Ray" in headers:
            results["cdn"] = "Cloudflare"
        elif "X-Amz-Cf-Id" in headers:
            results["cdn"] = "AWS CloudFront"
        elif "X-Azure-Ref" in headers:
            results["cdn"] = "Azure CDN"
        elif "X-Vercel-Id" in headers:
            results["cdn"] = "Vercel"

        # Güvenlik header'ları kontrolü
        for header in SECURITY_HEADERS:
            if header in headers:
                results["security_headers"][header] = headers[header]
            else:
                results["missing_headers"].append(header)
                results["issues"].append(f"Eksik güvenlik header'ı: {header}")
                results["score"] -= 5

        # Cloud provider tespiti (header'lardan)
        for provider, indicators in CLOUD_PROVIDERS.items():
            for indicator in indicators:
                if any(indicator in str(v) for v in headers.values()):
                    results["cloud_provider"] = provider
                    break

    except requests.exceptions.SSLError:
        results["issues"].append("SSL hatası — HTTPS bağlantısı kurulamadı")
        results["score"] -= 30

    except Exception as e:
        results["issues"].append(f"HTTP analizi yapılamadı: {str(e)}")
        results["score"] -= 20

    # Cloud provider tespiti (domain'den)
    if not results["cloud_provider"]:
        for provider, indicators in CLOUD_PROVIDERS.items():
            for indicator in indicators:
                if indicator in domain:
                    results["cloud_provider"] = provider
                    break

    results["score"] = max(0, results["score"])
    return results