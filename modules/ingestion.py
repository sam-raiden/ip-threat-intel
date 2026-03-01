import ipaddress


def validate_and_normalize_ip(ip_input: str) -> str:
    cleaned_ip = ip_input.strip()
    try:
        return str(ipaddress.ip_address(cleaned_ip))
    except ValueError:
        raise ValueError(f"Invalid IP address: '{cleaned_ip}'")