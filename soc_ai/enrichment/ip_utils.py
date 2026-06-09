import ipaddress
from typing import Optional, Tuple


def parse_ip(ip_value: str) -> Optional[ipaddress._BaseAddress]:
    """
    Parse a string into an IPv4 or IPv6 address object.
    Return None if the value is malformed.
    """
    if not ip_value or not isinstance(ip_value, str):
        return None

    ip_value = ip_value.strip()

    try:
        return ipaddress.ip_address(ip_value)
    except ValueError:
        return None


def classify_ip(ip_value: str) -> Tuple[str, str]:
    """
    Classify an IP address before external enrichment lookup.
    """
    ip_obj = parse_ip(ip_value)

    if ip_obj is None:
        return "invalid", "Malformed or empty IP address"

    if ip_obj.is_loopback:
        return "loopback", "Loopback IP address should not be enriched externally"

    if ip_obj.is_link_local:
        return "link_local", "Link-local IP address should not be enriched externally"

    if ip_obj.is_multicast:
        return "multicast", "Multicast IP address should not be enriched externally"

    if ip_obj.is_unspecified:
        return "unspecified", "Unspecified IP address should not be enriched externally"

    if ip_obj.is_reserved:
        return "reserved", "Reserved IP address should not be enriched externally"

    if ip_obj.is_private:
        return "private", "Private/internal IP address should not be enriched externally"

    return "valid_public", "Public IP address can be enriched externally"


def should_lookup_external(ip_value: str) -> bool:
    """
    Return True only if the IP is valid and public.
    """
    category, _ = classify_ip(ip_value)
    return category == "valid_public"