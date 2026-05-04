def calculate_score(dns_results, ssl_results, port_results, cloud_results, email_results):
    scores = {
        "dns": dns_results.get("score", 0),
        "ssl": ssl_results.get("score", 0),
        "ports": port_results.get("score", 0),
        "cloud": cloud_results.get("score", 0),
        "email": email_results.get("score", 0)
    }

    # Ağırlıklı ortalama
    weights = {
        "dns": 0.20,
        "ssl": 0.25,
        "ports": 0.25,
        "cloud": 0.15,
        "email": 0.15
    }

    total_score = sum(scores[k] * weights[k] for k in scores)
    total_score = round(total_score)

    # Güvenlik seviyesi
    if total_score >= 80:
        grade = "A"
        level = "Güvenli"
        color = "green"
    elif total_score >= 60:
        grade = "B"
        level = "Orta"
        color = "yellow"
    elif total_score >= 40:
        grade = "C"
        level = "Riskli"
        color = "orange"
    else:
        grade = "D"
        level = "Tehlikeli"
        color = "red"

    # Tüm sorunları topla
    all_issues = []
    all_issues.extend(dns_results.get("issues", []))
    all_issues.extend(ssl_results.get("issues", []))
    all_issues.extend(port_results.get("issues", []))
    all_issues.extend(cloud_results.get("issues", []))
    all_issues.extend(email_results.get("issues", []))

    return {
        "total_score": total_score,
        "grade": grade,
        "level": level,
        "color": color,
        "scores": scores,
        "all_issues": all_issues,
        "issue_count": len(all_issues)
    }