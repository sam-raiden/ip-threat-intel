import sys
import json

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from modules.pipeline_controller import run_pipeline

app = FastAPI()


@app.get("/scan-ip")
def scan_ip(ip: str) -> JSONResponse:
    try:
        result: dict = run_pipeline(ip)
        return JSONResponse(content=result)
    except ValueError as e:
        return JSONResponse(status_code=400, content={"error": str(e)})
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": f"Unexpected error: {str(e)}"})


def print_pretty_report(result: dict) -> None:
    summary = result.get("executive_summary", {})
    signals = result.get("threat_signals", {})
    vt = signals.get("virustotal", {})
    ab = signals.get("abuseipdb", {})
    otx = signals.get("otx", {})

    divider = "=" * 50

    print(divider)
    print("        ZERO-BUDGET IP THREAT INTEL REPORT")
    print(divider)
    print(f"IP Address: {result.get('ip_address', 'N/A')}")
    print()
    print("[ Executive Summary ]")
    print(f"Verdict    : {summary.get('verdict', 'N/A')} (Score: {summary.get('risk_score', 0)})")
    print(f"Confidence : {summary.get('confidence', 'N/A')}")
    print()
    print("[ Threat Signals ]")
    print()
    print("- VirusTotal")
    print(f"    Malicious Detections : {vt.get('malicious_detections', 0)}")
    print(f"    Reputation Score     : {vt.get('reputation_score')}")
    print(f"    Status               : {vt.get('status', 'N/A')}")
    print()
    print("- AbuseIPDB")
    print(f"    Abuse Confidence     : {ab.get('abuse_confidence_score', 0)}")
    print(f"    Total Reports        : {ab.get('total_reports', 0)}")
    print(f"    Status               : {ab.get('status', 'N/A')}")
    print()
    print("- OTX")
    print(f"    Pulse Count          : {otx.get('pulse_count', 0)}")
    print(f"    Status               : {otx.get('status', 'N/A')}")
    print()
    print(divider)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python app.py <ip_address>")
        sys.exit(1)

    ip_input: str = sys.argv[1]

    try:
        result: dict = run_pipeline(ip_input)
        print_pretty_report(result)
    except ValueError as e:
        print(f"Validation error: {str(e)}")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        sys.exit(1)