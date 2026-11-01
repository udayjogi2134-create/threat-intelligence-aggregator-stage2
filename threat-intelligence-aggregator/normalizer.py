"""Canonicalize supported IOCs without pretending normalization proves maliciousness."""
import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit

DOMAIN_LABEL = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")
HASH_LENGTHS = {32: "MD5", 40: "SHA1", 64: "SHA256"}

def normalize_ioc(kind: str, raw_value: str):
    kind = kind.strip().upper()
    value = str(raw_value).strip().strip('"').strip("'")
    if not value:
        raise ValueError("empty indicator")

    if kind == "IP":
        try:
            return str(ipaddress.ip_address(value))
        except ValueError as exc:
            raise ValueError("invalid IPv4/IPv6 address") from exc

    if kind == "HASH":
        value = value.lower()
        if len(value) not in HASH_LENGTHS or not re.fullmatch(r"[0-9a-f]+", value):
            raise ValueError("hash must be a 32, 40, or 64 character hexadecimal value")
        return value

    if kind == "DOMAIN":
        value = value.rstrip(".").encode("idna").decode("ascii").lower()
        if len(value) > 253 or "." not in value:
            raise ValueError("invalid domain")
        labels = value.split(".")
        if any(not DOMAIN_LABEL.fullmatch(label) for label in labels):
            raise ValueError("invalid domain label")
        if not labels[-1].isalpha() or len(labels[-1]) < 2:
            raise ValueError("invalid domain suffix")
        return value

    if kind == "EMAIL":
        if value.count("@") != 1:
            raise ValueError("invalid email address")
        local, domain = value.rsplit("@", 1)
        if not local or len(local) > 64:
            raise ValueError("invalid email local part")
        domain = normalize_ioc("DOMAIN", domain)
        return f"{local}@{domain}"

    if kind == "URL":
        try:
            parts = urlsplit(value)
            if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
                raise ValueError("URL must use http or https and include a host")
            if parts.username or parts.password:
                raise ValueError("URLs containing embedded credentials are not accepted")
            host = parts.hostname.encode("idna").decode("ascii").lower()
            try:
                ipaddress.ip_address(host)
            except ValueError:
                host = normalize_ioc("DOMAIN", host)
            port = parts.port
            if port and not ((parts.scheme.lower() == "http" and port == 80) or
                             (parts.scheme.lower() == "https" and port == 443)):
                netloc = f"{host}:{port}"
            else:
                netloc = host
            return urlunsplit((parts.scheme.lower(), netloc, parts.path or "/", parts.query, parts.fragment))
        except (UnicodeError, ValueError) as exc:
            raise ValueError(f"invalid URL: {exc}") from exc

    raise ValueError(f"unsupported IOC type: {kind}")
