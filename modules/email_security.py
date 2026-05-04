import dns.resolver

def analyze_email_security(domain):
    results = {
        "domain": domain,
        "spf": None,
        "dmarc": None,
        "dkim_exists": False,
        "mx_records": [],
        "issues": [],
        "recommendations": [],
        "score": 100
    }

    # SPF kontrolü
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        for r in answers:
            txt = r.to_text().strip('"')
            if txt.startswith("v=spf1"):
                results["spf"] = txt

                # SPF politika kontrolü
                if "-all" in txt:
                    pass  # En güvenli
                elif "~all" in txt:
                    results["recommendations"].append(
                        "SPF politikasını '-all' olarak güncelleyin"
                    )
                    results["score"] -= 5
                elif "?all" in txt or "+all" in txt:
                    results["issues"].append("SPF politikası çok gevşek!")
                    results["score"] -= 20

        if not results["spf"]:
            results["issues"].append("SPF kaydı bulunamadı")
            results["recommendations"].append(
                "SPF kaydı ekleyin: v=spf1 include:_spf.google.com -all"
            )
            results["score"] -= 25

    except Exception as e:
        results["issues"].append(f"SPF sorgulanamadı: {str(e)}")
        results["score"] -= 25

    # DMARC kontrolü
    try:
        dmarc_answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        for r in dmarc_answers:
            txt = r.to_text().strip('"')
            if "v=DMARC1" in txt:
                results["dmarc"] = txt

                # DMARC politika kontrolü
                if "p=reject" in txt:
                    pass  # En güvenli
                elif "p=quarantine" in txt:
                    results["recommendations"].append(
                        "DMARC politikasını 'p=reject' olarak güncelleyin"
                    )
                    results["score"] -= 5
                elif "p=none" in txt:
                    results["issues"].append("DMARC politikası 'none' — koruma yok!")
                    results["score"] -= 15

        if not results["dmarc"]:
            results["issues"].append("DMARC kaydı bulunamadı")
            results["recommendations"].append(
                "DMARC kaydı ekleyin: v=DMARC1; p=reject; rua=mailto:dmarc@domain.com"
            )
            results["score"] -= 25

    except Exception as e:
        results["issues"].append("DMARC kaydı bulunamadı")
        results["recommendations"].append(
            "DMARC kaydı ekleyin: v=DMARC1; p=reject"
        )
        results["score"] -= 25

    # DKIM kontrolü (yaygın selector'lar)
    dkim_selectors = ["default", "google", "mail", "dkim", "k1", "selector1", "selector2"]
    for selector in dkim_selectors:
        try:
            dns.resolver.resolve(f"{selector}._domainkey.{domain}", "TXT")
            results["dkim_exists"] = True
            break
        except:
            continue

    if not results["dkim_exists"]:
        results["issues"].append("DKIM kaydı tespit edilemedi")
        results["recommendations"].append("DKIM imzalama aktif edin")
        results["score"] -= 20

    # MX kayıtları
    try:
        mx_answers = dns.resolver.resolve(domain, "MX")
        results["mx_records"] = [r.exchange.to_text() for r in mx_answers]

        if not results["mx_records"]:
            results["issues"].append("MX kaydı bulunamadı")
            results["score"] -= 10

    except:
        results["issues"].append("MX kaydı bulunamadı")
        results["score"] -= 10

    results["score"] = max(0, results["score"])
    return results