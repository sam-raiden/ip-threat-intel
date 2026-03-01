from modules.ingestion import validate_and_normalize_ip
from modules.virustotal_service import query_virustotal
from modules.abuseipdb_service import query_abuseipdb
from modules.otx_service import query_otx
from modules.scoring_engine import calculate_risk_score
from modules.formatter import format_report


def run_pipeline(ip_input: str) -> dict:
    ip: str = validate_and_normalize_ip(ip_input)

    virustotal_data: dict = query_virustotal(ip)
    abuseipdb_data: dict = query_abuseipdb(ip)
    otx_data: dict = query_otx(ip)

    risk_data: dict = calculate_risk_score(virustotal_data, abuseipdb_data, otx_data)

    return format_report(
        ip=ip,
        virustotal_data=virustotal_data,
        abuseipdb_data=abuseipdb_data,
        otx_data=otx_data,
        risk_data=risk_data,
    )