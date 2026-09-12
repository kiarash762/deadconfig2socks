import base64
import ipaddress
import json
from urllib.parse import urlparse


def is_valid_ipv4(address: str) -> bool:
    """Check if the given string is a valid IPv4 address."""
    if not address:
        return False
    try:
        ip = ipaddress.ip_address(address.strip())
        return isinstance(ip, ipaddress.IPv4Address)
    except ValueError:
        return False


def clean_base64(data: str) -> str:
    """Normalize base64 padding and URL-safe characters."""
    data = data.strip().replace("-", "+").replace("_", "/")
    missing_padding = len(data) % 4
    if missing_padding:
        data += "=" * (4 - missing_padding)
    return data


def extract_ip_from_vmess(config: str) -> str | None:
    """Decode vmess config and extract the 'add' field."""
    try:
        b64_str = config[8:].strip()
        decoded_bytes = base64.b64decode(clean_base64(b64_str))
        decoded_text = decoded_bytes.decode("utf-8", errors="ignore")
        data = json.loads(decoded_text)
        return data.get("add")
    except Exception:
        return None


def extract_ip_from_standard_uri(config: str) -> str | None:
    """Extract hostname/IP from standard URI schemes."""
    try:
        parsed = urlparse(config)
        host = parsed.hostname
        if host:
            return host

        # Handle Shadowsocks links where user:password@host:port is base64-encoded
        if parsed.scheme == "ss" and not host and parsed.netloc:
            b64_part = parsed.netloc.split("@")[-1].split("#")[0]
            decoded = base64.b64decode(clean_base64(b64_part)).decode(
                "utf-8", errors="ignore"
            )
            if "@" in decoded:
                host_port = decoded.split("@")[-1]
                return host_port.split(":")[0]
    except Exception:
        pass
    return None


def extract_ip_from_ssr(config: str) -> str | None:
    """Decode ssr config and extract the host part."""
    try:
        b64_str = config[6:].strip()
        decoded = base64.b64decode(clean_base64(b64_str)).decode(
            "utf-8", errors="ignore"
        )
        return decoded.split(":")[0]
    except Exception:
        return None


def process_config(line: str) -> str | None:
    line = line.strip()
    if not line:
        return None

    extracted_host = None

    if line.startswith("vmess://"):
        extracted_host = extract_ip_from_vmess(line)
    elif line.startswith("ssr://"):
        extracted_host = extract_ip_from_ssr(line)
    elif any(
        line.startswith(proto)
        for proto in (
            "vless://",
            "trojan://",
            "ss://",
            "socks://",
            "socks5://",
            "hysteria2://",
            "hy2://",
            "tuic://",
        )
    ):
        extracted_host = extract_ip_from_standard_uri(line)

    if extracted_host and is_valid_ipv4(extracted_host):
        return extracted_host.strip()

    return None


def main():
    input_file = "config.txt"
    output_file = "ip.txt"
    unique_ips = set()

    try:
        with open(input_file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                ip = process_config(line)
                if ip:
                    unique_ips.add(ip)

        with open(output_file, "w", encoding="utf-8") as f:
            for ip in sorted(unique_ips):
                f.write(ip + "\n")

        print(
            f"Done: Successfully extracted {len(unique_ips)} valid IPv4 address(es) into '{output_file}'."
        )

    except FileNotFoundError:
        print(f"Error: Input file '{input_file}' not found.")


if __name__ == "__main__":
    main()