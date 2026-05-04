import dns.resolver
import dns.reversename

def analyze_dns(domain):
    results = {
        "domain": domain,
        "a_records": [],
        "mx_records": [],
        "ns_records": [],
        "txt_records": [],
        "spf": None,
        "dmarc": None,
        "dnssec": False,
        "issues": [],
        "score": 100
    }

    # A kayıtları
    try:
        answers = dns.resolver.resolve(domain, "A")
        results["a_records"] = [r.address for r in answers]
    except:
        results["issues"].append("A kaydı bulunamadı")
        results["score"] -= 20

    # MX kayıtları
    try:
        answers = dns.resolver.resolve(domain, "MX")
        results["mx_records"] = [r.exchange.to_text() for r in answers]
    except:
        results["issues"].append("MX kaydı bulunamadı")

    # NS kayıtları
    try:
        answers = dns.resolver.resolve(domain, "NS")
        results["ns_records"] = [r.target.to_text() for r in answers]
    except:
        results["issues"].append("NS kaydı bulunamadı")

    # TXT kayıtları
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        for r in answers:
            txt = r.to_text().strip('"')
            results["txt_records"].append(txt)

            # SPF kontrolü
            if txt.startswith("v=spf1"):
                results["spf"] = txt

        # DMARC kontrolü
        try:
            dmarc = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
            for r in dmarc:
                txt = r.to_text().strip('"')
                if "v=DMARC1" in txt:
                    results["dmarc"] = txt
        except:
            results["issues"].append("DMARC kaydı eksik")
            results["score"] -= 15

    except:
        results["issues"].append("TXT kaydı bulunamadı")

    # SPF kontrolü
    if not results["spf"]:
        results["issues"].append("SPF kaydı eksik")
        results["score"] -= 15

    # DNSSEC kontrolü
    try:
        answers = dns.resolver.resolve(domain, "DNSKEY")
        if answers:
            results["dnssec"] = True
    except:
        results["issues"].append("DNSSEC aktif değil")
        results["score"] -= 10

    results["score"] = max(0, results["score"])
    return results