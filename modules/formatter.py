_EMOJI_MAP: dict[str, str] = {
    "Low": "🟢",
    "Medium": "🟡",
    "High": "🟠",
    "Critical": "🔴",
}

_SUMMARY_MAP: dict[str, str] = {
    "Low": "No significant threat indicators detected",
    "Medium": "Moderate suspicious activity observed",
    "High": "Elevated threat intelligence indicators detected",
    "Critical": "Severe threat intelligence indicators detected",
}


def _resolve_status(error: str | None) -> str:
    if error is None:
        return "Operational"
    error_lower = error.lower()
    if "timeout" in error_lower:
        return "API Timeout"
    if "connection" in error_lower:
        return "API Unreachable"
    if "rate limit" in error_lower:
        return "Rate Limited"
    return "Error"


def format_report(
    ip: str,
    virustotal_data: dict,
    abuseipdb_data: dict,
    otx_data: dict,
    risk_data: dict,
) -> dict:
    risk_level: str = risk_data.get("risk_level", "Low")
    emoji: str = _EMOJI_MAP.get(risk_level, "⚪")
    score: int = risk_data.get("score", 0)

    sources = [virustotal_data, abuseipdb_data, otx_data]
    operational_count: int = sum(1 for s in sources if s.get("error") is None)

    return {
        "ip_address": ip,
        "executive_summary": {
            "verdict": f"{emoji} {risk_level.upper()} RISK",
            "risk_score": score,
            "confidence": f"{operational_count}/3 sources analyzed",
        },
        "threat_signals": {
            "virustotal": {
                "malicious_detections": virustotal_data.get("malicious_count", 0),
                "reputation_score": virustotal_data.get("reputation"),
                "status": _resolve_status(virustotal_data.get("error")),
            },
            "abuseipdb": {
                "abuse_confidence_score": abuseipdb_data.get("abuse_confidence_score", 0),
                "total_reports": abuseipdb_data.get("total_reports", 0),
                "status": _resolve_status(abuseipdb_data.get("error")),
            },
            "otx": {
                "pulse_count": otx_data.get("pulse_count", 0),
                "status": _resolve_status(otx_data.get("error")),
            },
        },
    }