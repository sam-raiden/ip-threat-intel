def calculate_risk_score(
    virustotal_data: dict,
    abuseipdb_data: dict,
    otx_data: dict,
) -> dict[str, int | str]:
    score: int = 0

    if virustotal_data.get("malicious_count", 0) > 5:
        score += 40

    if abuseipdb_data.get("abuse_confidence_score", 0) > 50:
        score += 30

    if otx_data.get("pulse_count", 0) > 0:
        score += 30

    if score >= 80:
        risk_level = "Critical"
    elif score >= 60:
        risk_level = "High"
    elif score >= 30:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    return {
        "score": score,
        "risk_level": risk_level,
    }