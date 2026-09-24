"""
siteaudit_core — honest, measurement-only website auditing.

Every finding this module reports was actually measured with a live HTTP
request: status codes, response latency, HTML tag presence, and TLS
certificate expiry. Nothing is inferred or invented, so anything built on
top of these results (reports, outreach drafts) can quote them truthfully.
"""
from __future__ import annotations

import re
import socket
import ssl
import time
from dataclasses import asdict, dataclass, field
from urllib.parse import urlparse

import requests

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
META_DESC_RE = re.compile(r'<meta[^>]+name=["\']description["\'][^>]*>', re.I)
VIEWPORT_RE = re.compile(r'<meta[^>]+name=["\']viewport["\'][^>]*>', re.I)
MAILTO_RE = re.compile(
    r"mailto:([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", re.I)
EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")

# Addresses we never surface as outreach targets.
EMAIL_BLOCKLIST_EXACT = set()
EMAIL_BLOCKLIST_SUBSTR = ("noreply", "no-reply", "donotreply", "do-not-reply",
                          "example.com", "example.org", "example.net",
                          "test.com", ".png", ".jpg", ".jpeg",
                          ".gif", ".webp", ".svg", "sentry", "schema.org",
                          "w3.org")
CONTACT_PATHS = ("/contact", "/contact-us", "/contact.html",
                 "/about/contact-us", "/about-us", "/about")
UA = {"User-Agent": "SiteAuditMCP/1.0 (+https://github.com/ZeroZen270/hermes-mcp)"}

ISSUE_LABELS = {
    "no_https": "site still serves over plain HTTP",
    "slow": "homepage loads slowly (>4s)",
    "no_title": "homepage has no <title> tag (hurts search)",
    "no_meta_description": "homepage has no meta description (hurts click-through)",
    "not_mobile_friendly": "no mobile viewport tag (poor mobile experience)",
    "server_error": "server is returning 5xx errors",
    "unreachable": "site is unreachable",
    "cert_expiring": "TLS certificate expires in under 14 days",
}


def _clean_email(raw: str) -> str | None:
    e = raw.strip().strip(".,;:!?\"'()[]<>").lower()
    if not EMAIL_RE.fullmatch(e):
        return None
    if e in EMAIL_BLOCKLIST_EXACT:
        return None
    if any(b in e for b in EMAIL_BLOCKLIST_SUBSTR):
        return None
    return e


def extract_emails(html: str, domain: str) -> list[str]:
    """Public contact emails found in page HTML. mailto: links first."""
    found: list[str] = []
    for raw in MAILTO_RE.findall(html):
        e = _clean_email(raw.split("?")[0])
        if e and e not in found:
            found.append(e)
    text = re.sub(r"<[^>]+>", " ", html)
    for raw in EMAIL_RE.findall(text):
        e = _clean_email(raw)
        if e and e not in found:
            found.append(e)
    same = [e for e in found if e.endswith("@" + domain)]
    other = [e for e in found if not e.endswith("@" + domain)]
    return (same + other)[:5]


@dataclass
class Audit:
    domain: str
    url: str
    issues: list[str] = field(default_factory=list)
    notes: dict = field(default_factory=dict)
    score: int = 0
    checked_ts: float = field(default_factory=time.time)
    emails: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["issue_labels"] = [ISSUE_LABELS.get(i, i) for i in self.issues]
        return d


def _cert_days_left(host: str) -> int | None:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert()
        import datetime
        exp = datetime.datetime.strptime(
            cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        return (exp - datetime.datetime.utcnow()).days
    except Exception:
        return None


def normalize_domain(raw: str) -> str:
    d = raw.strip().lower()
    for prefix in ("http://", "https://"):
        if d.startswith(prefix):
            d = d[len(prefix):]
    return d.split("/")[0].split("?")[0]


def audit_domain(domain: str, timeout: int = 12) -> Audit:
    """Audit one domain, returning only measured findings."""
    domain = normalize_domain(domain)
    if not domain or "." not in domain:
        raise ValueError(f"not a valid domain: {domain!r}")
    audit = Audit(domain=domain, url=f"https://{domain}")
    t0 = time.time()
    try:
        r = requests.get(f"https://{domain}", timeout=timeout,
                         allow_redirects=True, headers=UA)
        elapsed = time.time() - t0
        audit.notes["status"] = r.status_code
        audit.notes["latency_s"] = round(elapsed, 2)
        audit.notes["final_url"] = r.url
        if r.status_code >= 500:
            audit.issues.append("server_error")
        if elapsed > 4:
            audit.issues.append("slow")
        html = r.text[:200_000]
        if not TITLE_RE.search(html):
            audit.issues.append("no_title")
        if not META_DESC_RE.search(html):
            audit.issues.append("no_meta_description")
        if not VIEWPORT_RE.search(html):
            audit.issues.append("not_mobile_friendly")
        audit.emails = extract_emails(html, domain)
        if not audit.emails:
            base = f"{urlparse(r.url).scheme}://{urlparse(r.url).hostname}"
            for path in CONTACT_PATHS:
                try:
                    cr = requests.get(base + path, timeout=timeout,
                                      allow_redirects=True, headers=UA)
                    time.sleep(0.5)
                    if (cr.status_code == 200
                            and "text/html" in cr.headers.get("Content-Type", "")):
                        audit.emails = extract_emails(cr.text[:200_000], domain)
                        if audit.emails:
                            audit.notes["email_source"] = path
                            break
                except Exception:
                    continue
        days = _cert_days_left(urlparse(r.url).hostname or domain)
        if days is not None:
            audit.notes["cert_days_left"] = days
            if days < 14:
                audit.issues.append("cert_expiring")
    except requests.exceptions.SSLError:
        try:
            r = requests.get(f"http://{domain}", timeout=timeout, headers=UA)
            audit.issues.append("no_https")
            audit.notes["http_status"] = r.status_code
            audit.url = f"http://{domain}"
        except Exception:
            audit.issues.append("unreachable")
    except Exception as e:
        audit.issues.append("unreachable")
        audit.notes["error"] = str(e)[:120]

    weights = {"no_https": 5, "server_error": 5, "unreachable": 0,
               "slow": 3, "no_title": 2, "no_meta_description": 2,
               "not_mobile_friendly": 2, "cert_expiring": 3}
    audit.score = sum(weights.get(i, 1) for i in audit.issues)
    return audit


def find_contact_emails(domain: str, timeout: int = 12) -> dict:
    """Fetch homepage (+ contact pages) and return public contact emails."""
    domain = normalize_domain(domain)
    if not domain or "." not in domain:
        raise ValueError(f"not a valid domain: {domain!r}")
    try:
        r = requests.get(f"https://{domain}", timeout=timeout,
                         allow_redirects=True, headers=UA)
    except Exception:
        return {"domain": domain, "emails": [], "error": "unreachable"}
    emails = extract_emails(r.text[:200_000], domain)
    source = "homepage"
    if not emails:
        base = f"{urlparse(r.url).scheme}://{urlparse(r.url).hostname}"
        for path in CONTACT_PATHS:
            try:
                cr = requests.get(base + path, timeout=timeout,
                                  allow_redirects=True, headers=UA)
                time.sleep(0.5)
                if (cr.status_code == 200
                        and "text/html" in cr.headers.get("Content-Type", "")):
                    emails = extract_emails(cr.text[:200_000], domain)
                    if emails:
                        source = path
                        break
            except Exception:
                continue
    return {"domain": domain, "emails": emails, "source": source}


def draft_outreach(domain: str, sender_name: str = "Aaron Svoboda",
                   sender_business: str = "Technology Squared LLC",
                   timeout: int = 12) -> dict:
    """Draft a short outreach email quoting ONLY measured audit findings.

    Returns the draft plus the raw findings it was built from, so the
    sender can verify every claim before sending.
    """
    audit = audit_domain(domain, timeout=timeout)
    findings = [ISSUE_LABELS.get(i, i) for i in audit.issues]
    if audit.issues:
        body_lines = [
            f"Hi — quick note on {audit.domain}: I measured a few concrete",
            "issues on your site just now:",
            "",
        ]
        body_lines += [f"• {label}" for label in findings]
        body_lines += [
            "",
            "I do small fixed-price website fixes (speed, mobile, SEO basics)",
            "for local businesses — happy to fix these for a flat fee, and",
            "you only pay if the fixes measurably improve things.",
            "",
            f"— {sender_name}, {sender_business}",
        ]
    else:
        body_lines = [
            f"Hi — I ran a quick technical check on {audit.domain} and it",
            "looks solid (fast, mobile-friendly, valid HTTPS). No pitch —",
            "just wanted to say the site is in good shape.",
            "",
            f"— {sender_name}, {sender_business}",
        ]
    return {
        "domain": audit.domain,
        "to": audit.emails[0] if audit.emails else None,
        "to_candidates": audit.emails,
        "subject": f"Quick technical note on {audit.domain}",
        "body": "\n".join(body_lines),
        "findings": audit.to_dict(),
        "warning": ("No public contact email found — do not guess one."
                    if not audit.emails else None),
    }
