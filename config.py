import os


def _require_env(key: str) -> str:
    value = os.environ.get(key)
    if not value:
        raise RuntimeError(f"Missing required environment variable: {key}")
    return value


VIRUSTOTAL_API_KEY: str = _require_env("VIRUSTOTAL_API_KEY")
ABUSEIPDB_API_KEY: str = _require_env("ABUSEIPDB_API_KEY")
OTX_API_KEY: str = _require_env("OTX_API_KEY")

VIRUSTOTAL_RATE_LIMIT_PER_MIN: int = 4
ABUSEIPDB_RATE_LIMIT_PER_DAY: int = 1000
OTX_RATE_LIMIT_PER_MIN: int = 5