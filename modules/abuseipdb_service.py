import requests

import config
from modules.rate_limiter import RateLimiter

_rate_limiter = RateLimiter(requests_per_day=config.ABUSEIPDB_RATE_LIMIT_PER_DAY)

_BASE_URL = "https://api.abuseipdb.com/api/v2/check"


def query_abuseipdb(ip: str) -> dict[str, int | str | None]:
    try:
        _rate_limiter.allow_request()
    except RuntimeError as e:
        return {
            "source": "abuseipdb",
            "abuse_confidence_score": 0,
            "total_reports": 0,
            "error": str(e),
        }

    try:
        response = requests.get(
            _BASE_URL,
            headers={
                "Key": config.ABUSEIPDB_API_KEY,
                "Accept": "application/json",
            },
            params={
                "ipAddress": ip,
                "maxAgeInDays": 90,
            },
            timeout=10,
        )
        response.raise_for_status()
        data = response.json().get("data", {})

        abuse_confidence_score: int = data.get("abuseConfidenceScore", 0)
        total_reports: int = data.get("totalReports", 0)

        return {
            "source": "abuseipdb",
            "abuse_confidence_score": abuse_confidence_score,
            "total_reports": total_reports,
            "error": None,
        }

    except requests.exceptions.HTTPError as e:
        status_code = e.response.status_code
        if status_code == 429:
            error = "AbuseIPDB API rate limit exceeded"
        elif status_code == 403:
            error = "AbuseIPDB API quota exceeded or access forbidden"
        else:
            error = f"HTTP error: {status_code}"
        return {
            "source": "abuseipdb",
            "abuse_confidence_score": 0,
            "total_reports": 0,
            "error": error,
        }
    except requests.exceptions.ConnectionError:
        return {
            "source": "abuseipdb",
            "abuse_confidence_score": 0,
            "total_reports": 0,
            "error": "Connection error: unable to reach AbuseIPDB",
        }
    except requests.exceptions.Timeout:
        return {
            "source": "abuseipdb",
            "abuse_confidence_score": 0,
            "total_reports": 0,
            "error": "Request timed out",
        }
    except (KeyError, ValueError) as e:
        return {
            "source": "abuseipdb",
            "abuse_confidence_score": 0,
            "total_reports": 0,
            "error": f"Response parsing error: {str(e)}",
        }
    except Exception as e:
        return {
            "source": "abuseipdb",
            "abuse_confidence_score": 0,
            "total_reports": 0,
            "error": f"Unexpected error: {str(e)}",
        }