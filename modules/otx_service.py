import requests

import config
from modules.rate_limiter import RateLimiter

_rate_limiter = RateLimiter(requests_per_minute=config.OTX_RATE_LIMIT_PER_MIN)

_BASE_URL = "https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"


def query_otx(ip: str) -> dict[str, int | str | None]:
    try:
        _rate_limiter.allow_request()
    except RuntimeError as e:
        return {
            "source": "otx",
            "pulse_count": 0,
            "error": str(e),
        }

    try:
        response = requests.get(
            _BASE_URL.format(ip=ip),
            headers={"X-OTX-API-KEY": config.OTX_API_KEY},
            timeout=10,
        )
        response.raise_for_status()
        data = response.json()

        pulse_count: int = data.get("pulse_info", {}).get("count", 0)

        return {
            "source": "otx",
            "pulse_count": pulse_count,
            "error": None,
        }

    except requests.exceptions.HTTPError as e:
        status_code = e.response.status_code
        if status_code == 429:
            error = "OTX API rate limit exceeded"
        elif status_code == 403:
            error = "OTX API quota exceeded or access forbidden"
        else:
            error = f"HTTP error: {status_code}"
        return {
            "source": "otx",
            "pulse_count": 0,
            "error": error,
        }
    except requests.exceptions.ConnectionError:
        return {
            "source": "otx",
            "pulse_count": 0,
            "error": "Connection error: unable to reach AlienVault OTX",
        }
    except requests.exceptions.Timeout:
        return {
            "source": "otx",
            "pulse_count": 0,
            "error": "Request timed out",
        }
    except (KeyError, ValueError) as e:
        return {
            "source": "otx",
            "pulse_count": 0,
            "error": f"Response parsing error: {str(e)}",
        }
    except Exception as e:
        return {
            "source": "otx",
            "pulse_count": 0,
            "error": f"Unexpected error: {str(e)}",
        }