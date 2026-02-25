#!/usr/bin/env python3

import hashlib
import secrets
import socket
import ssl
import json
import re
from typing import Any

from utils.style import Colors
from utils.utils import configure_logger, re, requests, string, urlparse

logger = configure_logger(__name__)

CF_VIA_REGEX=re.compile(r'1\.1 [a-f0-9]+\.cloudfront\.net \(cloudfront\)')

def normalize_html(body: str | bytes) -> bytes:
    if isinstance(body, str):
        body = body.encode("utf-8")
    text = re.sub(rb"\s+", b" ", body)
    return text.strip()


def body_hash(body: str | bytes) -> str:
    """Generates a blake2 hash of the normalized body"""
    return hashlib.blake2b(normalize_html(body), digest_size=16).hexdigest()


def diff_headers(
    h1: Any,
    h2: Any,
    keys: list[str] = [
        "server",
        "via",
        "x-cache",
        "location",
        "cf-cache-status",
        "x-powered-by",
    ],
) -> dict[str, tuple]:
    """Compare important headers between two responses"""
    diffs: dict[str, tuple[Any, Any]] = {}
    for key in [x.title() for x in keys]:
        val1, val2 = h1.get(key), h2.get(key)
        if val1 and val2 and CF_VIA_REGEX.search(val1.lower()) and CF_VIA_REGEX.search(val2.lower()):
            pass 
        elif val1 != val2:
            diffs[key] = (val1, val2)
    return diffs


def extract_signals(html: str) -> dict[str, str]:
    """Extract important signals from HTML (title, canonical, etc.)"""
    signals: dict[str, str] = {}
    if not html:
        return signals

    try:
        title_match = re.search(
            r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL
        )
        if title_match:
            signals["title"] = title_match.group(1).strip()

        canonical_match = re.search(
            r'<link[^>]*rel=["\']canonical["\'][^>]*href=["\']([^"\']+)["\']',
            html,
            re.IGNORECASE,
        )
        if canonical_match:
            signals["canonical"] = canonical_match.group(1)

        og_match = re.search(
            r'<meta[^>]*property=["\']og:url["\'][^>]*content=["\']([^"\']+)["\']',
            html,
            re.IGNORECASE,
        )
        if og_match:
            signals["og:url"] = og_match.group(1)

    except Exception as e:
        logger.debug(f"Error extracting signals: {e}")

    return signals


def get_origin_ip(host: str) -> str | None:
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None


def get_vhost_via_ip(host: str, s: requests.Session, scheme: str = "http", path: str = "/") -> Any:
    """Access the vhost via IP with Host header"""
    ip = get_origin_ip(host)
    if not ip:
        return None

    if path.startswith("/") and scheme.endswith("/"):
        path = path[1:]
    elif not path.startswith("/") and not scheme.endswith("/"):
        path = "/" + path

    url_ip = f"{scheme}://{ip}{path}"
    try:
        ip_req = s.get(url_ip, timeout=10, verify=False, headers={"Host": host})
        return ip_req
    except Exception as e:
        logger.debug(f"Error accessing {url_ip}: {e}")
        return None


def rand_host(base: str) -> str:
    """Generates a random host in the same apex domain"""
    label = "".join(secrets.choice(string.ascii_lowercase) for _ in range(10))
    parts = base.split(".")
    if len(parts) >= 2:
        apex = ".".join(parts[-2:])
        return f"{label}.{apex}"
    else:
        return f"{label}.{base}"


def probe_host(url: str, s: requests.Session, host: str, header='Host') -> Any:
    """Test with a random host to detect wildcards"""
    try:
        r = s.get(url, headers={header: host}, timeout=10, verify=False)
        return r
    except Exception as e:
        logger.debug(f"Error with random host {host}: {e}")
        return None


def get_cert_san(host: str, port: int = 443) -> dict[str, Any] | None:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()

        if not cert:
            return None

        san = []
        subject_alt_name: Any = cert.get("subjectAltName", [])
        if subject_alt_name and isinstance(subject_alt_name, (list, tuple)):
            for entry in subject_alt_name:
                if isinstance(entry, tuple) and len(entry) == 2:
                    typ, names = entry
                    if typ == "DNS":
                        san.append(names)

        subject_info: Any = cert.get("subject", [])
        subject = {}
        if subject_info and isinstance(subject_info, (list, tuple)):
            for item in subject_info:
                if (
                    isinstance(item, tuple)
                    and len(item) == 1
                    and isinstance(item[0], tuple)
                ):
                    key, value = item[0]
                    subject[key] = value

        issuer_info: Any = cert.get("issuer", [])
        issuer = {}
        if issuer_info and isinstance(issuer_info, (list, tuple)):
            for item in issuer_info:
                if (
                    isinstance(item, tuple)
                    and len(item) == 1
                    and isinstance(item[0], tuple)
                ):
                    key, value = item[0]
                    issuer[key] = value

        return {"subject_cn": subject.get("commonName"), "san": san, "issuer": issuer}
    except Exception as e:
        logger.debug(f"Error getting cert for {host}: {e}")
        return None


def compare_responses(
    resp1: Any, resp2: Any, url1: str, url2: str
) -> dict[str, Any] | None:
    if not resp1 or not resp2:
        return None

    host1 = urlparse(url1).netloc
    host2 = urlparse(url2).netloc

    hash1 = body_hash(resp1.content)
    hash2 = body_hash(resp2.content)

    header_diffs = diff_headers(resp1.headers, resp2.headers)

    content1 = resp1.content.decode("utf-8", errors="ignore")
    content2 = resp2.content.decode("utf-8", errors="ignore")
    signals1 = extract_signals(content1)
    signals2 = extract_signals(content2)

    is_different = (
        hash1 != hash2
        or (host1 in content1 and host2 in content2)
        or (host1 in str(resp1.headers) and host2 in str(resp2.headers))
        or header_diffs
        or signals1.get("canonical") != signals2.get("canonical")
        or signals1.get("title") != signals2.get("title")
        or resp1.status_code != resp2.status_code
    )

    if is_different:
        return {
            "url1": url1,
            "url2": url2,
            "status1": resp1.status_code,
            "status2": resp2.status_code,
            "size1": len(resp1.content),
            "size2": len(resp2.content),
            "hash1": hash1,
            "hash2": hash2,
            "header_diffs": header_diffs,
            "signals1": signals1,
            "signals2": signals2,
            "differences": {
                "hash": hash1 != hash2,
                "header_diffs": len(header_diffs) > 0,
                "canonical": signals1.get("canonical") != signals2.get("canonical"),
                "title": signals1.get("title") != signals2.get("title"),
                "status_code": resp1.status_code != resp2.status_code,
                "body_reflected": (host1 in content1 and host2 in content2),
                "header_reflected": (host1 in str(resp1.headers) and host2 in str(resp2.headers))
            },
        }

    return None


def check_vhost(url: str, s: requests.Session, **kwargs) -> None:
    parsed_url = urlparse(url)
    host = parsed_url.netloc
    scheme = parsed_url.scheme

    test_paths = ["/", "/robots.txt", "/favicon.ico", "/.well-known/security.txt"]

    results = []

    try:
        baseline_resp = s.get(url, verify=False, timeout=10)

        print(" ├─ Testing IP + Host header access")
        for path in test_paths:
            if path == "/":
                test_url_original = url
            else:
                test_url_original = url.rstrip("/") + path

            try:
                original_resp = s.get(
                    test_url_original, verify=False, timeout=10
                )
            except Exception as e:
                logger.debug(
                    f"Error getting original response for {test_url_original}: {e}"
                )
                continue

            ip_resp = get_vhost_via_ip(host, s, scheme, path)
            if ip_resp:
                ip_test_url = f"{scheme}://{get_origin_ip(host)}{path}"
                comparison = compare_responses(
                    original_resp, ip_resp, test_url_original, ip_test_url
                )
                if comparison:
                    print(
                        f" │  └─ {Colors.YELLOW}[IP+HOST]{Colors.RESET} {comparison['url1']} <> {comparison['url2']}"
                    )
                    print(
                        f" │      Status: {comparison['status1']} <> {comparison['status2']}, Size: {comparison['size1']}b vs {comparison['size2']}b"
                    )
                    results.append(comparison)

        print(" ├─ Testing original basic vhosts")
        domain_clean = host if not host.startswith("www.") else host[4:]

        original_vhosts = [
            f"https://{domain_clean}/",
            f"http://{domain_clean}/",
            f"http://www2.{domain_clean}/",
            f"http://www3.{domain_clean}/",
            f"https://www2.{domain_clean}/",
            f"https://www3.{domain_clean}/",
        ]

        for vh in original_vhosts:
            try:
                req_vh = s.get(vh, verify=False, timeout=10)
                if req_vh.status_code not in [404, 403, 425, 503, 500, 400] and len(
                    req_vh.content
                ) not in range(
                    len(baseline_resp.content) - 100, len(baseline_resp.content) + 100
                ):
                    print(
                        f" │  └─ {Colors.GREEN}[ORIGINAL]{Colors.RESET} {url} [{baseline_resp.status_code}] [{len(baseline_resp.content)}b] <> {vh} [{req_vh.status_code}] [{len(req_vh.content)}b]"
                    )

                    comparison = compare_responses(baseline_resp, req_vh, url, vh)
                    if comparison:
                        if comparison["signals1"].get("title") != comparison[
                            "signals2"
                        ].get("title"):
                            print(
                                f" │      Titles: '{comparison['signals1'].get('title', 'N/A')}' vs '{comparison['signals2'].get('title', 'N/A')}'"
                            )
                        results.append(comparison)
            except Exception:
                continue

        print(" ├─ Testing wildcard with several hosts")
        for new_host_name in [
            rand_host(host),
            ".".join(["".join(secrets.choice(string.ascii_lowercase) for _ in range(10)), host]),
            f"{host}:8080",
            "",
            f"target.com\0{host}",
            f" {host}",
            f"\t{host}"
        ]:
            resp = probe_host(url, s, new_host_name)
            if resp:
                new_host_name = new_host_name.replace('\0', '%00')
                comparison = compare_responses(
                    baseline_resp, resp, url, f"http://{new_host_name}/"
                )
                if comparison:
                    print(
                        f" │  └─ {Colors.YELLOW}[WILDCARD]{Colors.RESET} Wildcard detected with host: {new_host_name}"
                    )
                    print(
                        f" │      Status: {comparison['status2']}, Size: {comparison['size2']}b"
                    )
                    results.append(comparison)
                else:
                    print(
                        f" │  └─ Host {new_host_name} returns same content (likely wildcard)"
                    )

        print(" ├─ Testing wildcard with several headers")
        random_host = rand_host(host)
        for header_name in [
            "X-Forwarded-For",
            "X-Forwarded-For-Original",
            "X-Forwarded-Host",
            "X-Host",
        ]:
            resp = probe_host(url, s, random_host, header_name)
            if resp:
                comparison = compare_responses(
                    baseline_resp, resp, url, f"http://{random_host}"
                )
                if comparison:
                    print(
                        f" │  └─ {Colors.YELLOW}[WILDCARD]{Colors.RESET} Wildcard detected with header: {header_name}"
                    )
                    print(
                        f" │      Status: {comparison['status2']}, Size: {comparison['size2']}b"
                    )
                    results.append(comparison)
                else:
                    print(
                        f" │  └─ Header {header_name} returns same content (likely wildcard)"
                    )

        if scheme == "https":
            print(" ├─ Analyzing SSL certificate")
            cert_info = get_cert_san(host)
            if cert_info:
                print(f" │  └─ Certificate CN: {cert_info.get('subject_cn')}")
                if cert_info.get("san"):
                    print(
                        f" │      SANs: {', '.join(cert_info['san'][:5])}"
                        + ("..." if len(cert_info["san"]) > 5 else "")
                    )

                    for san in cert_info["san"][:3]:
                        if san != host and not san.startswith("*."):
                            san_url = f"{scheme}://{san}/"
                            try:
                                san_resp = s.get(
                                    san_url, verify=False, timeout=10
                                )
                                comparison = compare_responses(
                                    baseline_resp, san_resp, url, san_url
                                )
                                if comparison:
                                    print(
                                        f" │      {Colors.BLUE}[SAN]{Colors.RESET} Different content on SAN: {san}"
                                    )
                                    results.append(comparison)
                            except Exception:
                                continue
    except Exception:
        logger.exception("Exception in vhost checker")

    with open('check_vhost.json', 'w') as fp:
        json.dump(results, fp)