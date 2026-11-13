#!/usr/bin/env python3
"""Module dung chung cho bo kiem thu phong thu CVE-2026-111497 (Node2Shell Lab)."""

import os
import urllib.request
import urllib.error
from typing import Tuple, Dict, Optional

# Cau hinh dia chi muc tieu trong Lab (co the ghi de bang bien moi truong)
WAF_URL = os.environ.get("LAB_WAF_URL", "http://localhost:8080")
DIRECT_APP_URL = os.environ.get("LAB_DIRECT_URL", "http://localhost:3000")
FALCO_CONTAINER = os.environ.get("LAB_FALCO_CONTAINER", "lab-falco-edr")

# Bang mau hien thi Terminal
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


def http_request(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    data: Optional[bytes] = None,
    timeout: int = 5
) -> Tuple[int, Dict[str, str], str]:
    """Gui HTTP request va tra ve (status_code, headers_dict, body_text)."""
    req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            resp_headers = {k.lower(): v for k, v in resp.info().items()}
            return resp.getcode(), resp_headers, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        resp_headers = {k.lower(): v for k, v in e.headers.items()} if e.headers else {}
        return e.code, resp_headers, e.read().decode("utf-8", errors="replace")
    except urllib.error.URLError as e:
        return 0, {}, f"Connection Error: {e.reason}"
    except Exception as e:
        return -1, {}, str(e)


def print_banner(title: str) -> None:
    print(f"\n{CYAN}{BOLD}{'=' * 74}{RESET}")
    print(f"{CYAN}{BOLD}  {title}{RESET}")
    print(f"{CYAN}{BOLD}{'=' * 74}{RESET}")
