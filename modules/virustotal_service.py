import requests

import config
from modules.rate_limiter import RateLimiter

_rate_limiter = RateLimiter(requests_per_minute=config.VIRUSTOTAL_RATE_LIMIT_PER_MIN)

_BASE_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"


def query_virustotal(ip: str) -> dict[str, int | str | None]:
    try:
        _rate_limiter.allow_request()
    except RuntimeError as e:
        return {
            "source": "virustotal",
            "malicious_count": 0,
            "reputation": None,
            "error": str(e),
        }

    try:
        response = requests.get(
            _BASE_URL.format(ip=ip),
            headers={"x-apikey": config.VIRUSTOTAL_API_KEY},
            timeout=10,
        )
        response.raise_for_status()
        data = response.json()

        attributes = data.get("data", {}).get("attributes", {})
        malicious_count: int = attributes.get("last_analysis_stats", {}).get("malicious", 0)
        reputation: int | None = attributes.get("reputation")

        return {
            "source": "virustotal",
            "malicious_count": malicious_count,
            "reputation": reputation,
            "error": None,
        }

    except requests.exceptions.HTTPError as e:
        status_code = e.response.status_code
        if status_code == 429:
            error = "VirusTotal API rate limit exceeded"
        elif status_code == 403:
            error = "VirusTotal API quota exceeded or access forbidden"
        else:
            error = f"HTTP error: {status_code}"
        return {
            "source": "virustotal",
            "malicious_count": 0,
            "reputation": None,
            "error": error,
        }
    except requests.exceptions.ConnectionError:
        return {
            "source": "virustotal",
            "malicious_count": 0,
            "reputation": None,
            "error": "Connection error: unable to reach VirusTotal",
        }
    except requests.exceptions.Timeout:
        return {
            "source": "virustotal",
            "malicious_count": 0,
            "reputation": None,
            "error": "Request timed out",
        }
    except (KeyError, ValueError) as e:
        return {
            "source": "virustotal",
            "malicious_count": 0,
            "reputation": None,
            "error": f"Response parsing error: {str(e)}",
        }
    except Exception as e:
        return {
            "source": "virustotal",
            "malicious_count": 0,
            "reputation": None,
            "error": f"Unexpected error: {str(e)}",
        }