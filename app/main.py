from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from email import policy
from email.parser import BytesParser
from email.message import Message, EmailMessage
from pydantic import BaseModel
import json
import os
import uuid
import httpx
import re
import asyncio
from pathlib import Path
from typing import List, Optional
from ipaddress import ip_address, IPv4Address, IPv6Address
from difflib import SequenceMatcher
import pyclamd

RSPAMD_HOST = os.getenv("RSPAMD_HOST", "rspamd")
CLAMAV_HOST = os.getenv("CLAMAV_HOST", "clamav")
EMAIL_ANALYSIS_DIR = Path(os.getenv("EMAIL_ANALYSIS_DIR", "/data/email-analysis"))
CACHE_MAPS = os.getenv("CACHE_MAPS", "true").lower() == "true"
MAP_CACHE_DIR = EMAIL_ANALYSIS_DIR / "maps_cache"
MAP_CACHE_DIR.mkdir(parents=True, exist_ok=True)
MAPBOX_TOKEN = os.getenv("MAPBOX_TOKEN")


app = FastAPI(title="FastAPI Orchestration Layer Daemon (FOLD)", version="0.8.0")

app.mount("/analysis-results", StaticFiles(directory=str(EMAIL_ANALYSIS_DIR)), name="analysis")

# Initialize CORS middleware to allow requests from any origin (for testing purposes)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Pydantic models
class DiffCheckRequest(BaseModel):
    suspicious_email_id: str
    legitimate_email_id: str

# Rspamd helpers
async def scan_with_rspamd(raw_email: bytes) -> dict:
    url = f"http://{RSPAMD_HOST}:11333/checkv2"

    # Create settings object
    settings = {
        # Disable irrelevant scores
        "scores" : {
            "DATE_IN_PAST": 0.0,
            "DATE_IN_FUTURE": 0.0,
            "HFILTER_HOSTNAME_UNKNOWN": 0.0,
        }
    }

    # Create header object
    headers = {
        "Content-Type": "message/rfc822",
        "Flags": "extended",
        # Include settings
        "Settings": json.dumps(settings),
    }

    async with httpx.AsyncClient() as client:
        response = await client.post(
            url,
            content=raw_email,
            headers=headers,
            timeout=30.0,
        )
        response.raise_for_status()
        return response.json()
    
def parse_rspamd_symbols(symbols: dict) -> dict:
    """
    Normalize the Rspamd symbols dict into a cleaner structure.
    Each symbol value from checkv2 looks like:
      {
        "score": 1.5,
        "metric_score": 1.5,
        "description": "Some description",
        "options": ["opt1", "opt2"]   # not always present
      }
    """
    parsed = {}
    for name, data in symbols.items():
        if not isinstance(data, dict):
            parsed[name] = {"score": data}
            continue
        parsed[name] = {
            "score": data.get("score", 0.0),
            "metric_score": data.get("metric_score"),
            "description": data.get("description", ""),
            "options": data.get("options", []),
        }
    return parsed

def parse_rspamd_response(result: dict) -> dict:
    """
    Extract and normalize all useful fields from Rspamd's /checkv2 response.

    Rspamd checkv2 response fields:
      score, required_score, action       — the verdict
      symbols                             — dict of triggered rules
      urls, emails                        — extracted from body
      dkim                                — DKIM result string
      subject                             — detected/rewritten subject
      message-id                          — Message-ID header value
      messages                            — dict of smtp/milter messages (NOT a list)
      milter                              — milter actions Rspamd wants to apply
      sender_ip                           — IP Rspamd pulled from Received headers
      headers                             — rewritten/added headers Rspamd suggests
      groups                              — symbol groups with aggregate scores
    """
    if "error" in result:
        return {"error": result["error"]}

    raw_symbols = result.get("symbols", {})
    symbols = parse_rspamd_symbols(raw_symbols) if isinstance(raw_symbols, dict) else {}

    # `messages` is a dict like {"smtp_message": "..."}, not a list
    raw_messages = result.get("messages", {})
    messages = raw_messages if isinstance(raw_messages, dict) else {}

    return {
        # Core verdict
        "score": result.get("score"),
        "required_score": result.get("required_score", 15.0),
        "action": result.get("action"),

        # Rule hits
        "symbols": symbols,
        "groups": result.get("groups", {}),

        # Extracted content
        "urls": result.get("urls", []),
        "emails": result.get("emails", []),

        # Auth / identity
        "dkim": result.get("dkim"),
        "sender_ip": result.get("sender_ip"),   # Rspamd's own IP extraction

        # Message metadata Rspamd saw
        "subject": result.get("subject"),
        "message_id": result.get("message-id"),

        # Milter / SMTP instructions
        "messages": messages,
        "milter": result.get("milter"),

        # Suggested header changes
        "headers": result.get("headers", {}),
    }

# Email parsing helpers
def generate_email_id() -> str:
    '''
    Generate unique email ID
    
    :return: email_id
    :rtype: str
    '''
    return str(uuid.uuid4())


def extract_headers(msg: Message) -> str:
    '''
    Extract email headers and format as text
    
    :return: headers_text
    :rtype: str
    '''
    headers = []
    for key, value in msg.items():
        headers.append(f"{key}: {value}")
    return "\n".join(headers)


def extract_sender_ips(msg: Message) -> List[str]:
    candidate_headers = [
        "Received", "X-Received", "Received-SPF",
        "Authentication-Results", "ARC-Authentication-Results",
        "X-Forefront-Antispam-Report",
    ]

    ip_pattern = re.compile(r"\b(?:\d{1,3}(?:\.\d{1,3}){3}|[A-Fa-f0-9:]{2,})\b")
    sender_ips: List[str] = []
    seen = set()

    for header_name in candidate_headers:
        for header_value in msg.get_all(header_name, []):
            for raw_ip in ip_pattern.findall(header_value):
                try:
                    # 1. Basic normalization
                    ip_obj = ip_address(raw_ip.split("%", 1)[0])

                    # 2. Handle 6to4 Tunneling (2002::/16)
                    if isinstance(ip_obj, IPv6Address) and ip_obj.sixtofour:
                        ip_obj = ip_obj.sixtofour
                    
                    # 3. Handle IPv4-Mapped IPv6 (::ffff:192.168.1.1)
                    if isinstance(ip_obj, IPv6Address) and ip_obj.ipv4_mapped:
                        ip_obj = ip_obj.ipv4_mapped

                    # 4. Bogon Filtering
                    if any([
                        ip_obj.is_private,      # Internal networks
                        ip_obj.is_loopback,     # Localhost
                        ip_obj.is_link_local,   # Self-assigned (169.254)
                        ip_obj.is_multicast,    # Multicast groups
                        ip_obj.is_reserved,     # Future use
                        ip_obj.is_unspecified   # 0.0.0.0
                    ]):
                        continue

                    normalized_ip = str(ip_obj)

                    if normalized_ip not in seen:
                        seen.add(normalized_ip)
                        sender_ips.append(normalized_ip)

                except ValueError:
                    continue

    return sender_ips

async def analyze_sender_ip(ip: str) -> dict:
    try:
        # Url with specific fields to minimize response size and focus on relevant data
        url = (
            f"http://ip-api.com/json/{ip}"
            "?fields=status,message,continent,country,regionName,city,lat,lon,isp,org,as,reverse,mobile,proxy,hosting,query"
        )

        # Use httpx with a timeout to avoid hanging on slow responses. Set a reasonable timeout just in case.
        async with httpx.AsyncClient() as client:
            response = await client.get(url, timeout=10.0)
            response.raise_for_status()

        # Validate response format and content
        details = response.json()
        if not isinstance(details, dict):
            return {"query": ip, "error": "Unexpected response format from ip-api"}

        # Check for API-level errors in the response
        if details.get("status") != "success":
            return {
                "query": ip,
                "status": details.get("status", "fail"),
                "message": details.get("message", "Unknown error"),
            }

        return details
    except Exception as e:
        return {"query": ip, "error": str(e)}

async def get_map_for_ip(ip: str, lat: float, lon: float, email_id: str, current_analysis_dir: Path):
    """
    Handles Mapbox logic with a global cache toggle.
    """
    # 1. Define the global cache path based on IP (so multiple emails can share it)
    cache_filename = f"map_{ip.replace(':', '_')}.png"
    global_cache_path = MAP_CACHE_DIR / cache_filename
    
    # 2. Target path inside the specific email's folder
    report_map_path = current_analysis_dir / f"map-{email_id}.png"

    # 3. Check if we can use the cache
    if CACHE_MAPS and global_cache_path.exists():
        # Copy from global cache to the specific report folder
        report_map_path.write_bytes(global_cache_path.read_bytes())
        return str(report_map_path)

    # 4. Fetch from Mapbox if not cached or if caching is disabled
    url = f"https://api.mapbox.com/styles/v1/mapbox/outdoors-v12/static/pin-s+ff0000({lon},{lat})/{lon},{lat},8.3/600x400@2x"
    params = { 
                "access_token": MAPBOX_TOKEN,
                "logo": "false",
                "attribution": "false",
              }

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url, params=params, timeout=10.0)
            if response.status_code == 200:
                # Save to specific report folder
                report_map_path.write_bytes(response.content)
                
                # If caching is enabled, also save to global cache
                if CACHE_MAPS:
                    global_cache_path.write_bytes(response.content)
                
                return str(report_map_path)
        except Exception as e:
            print(f"Mapbox error: {e}")
    
    return None

def extract_body(msg: Message) -> str:
    '''
    Extract email body and format as text
    
    :return: body_text
    :rtype: str
    '''
    body_parts = []

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition", ""))

            # Skip attachments
            if "attachment" in content_disposition:
                continue
            
            # Extract text/plain or text/html
            if content_type == "text/plain" or content_type == "text/html":
                try:
                    payload = part.get_payload(decode=True)
                    if isinstance(payload, bytes):
                        if payload:
                            charset = part.get_content_charset() or 'utf-8'
                            body_parts.append(f"--- {content_type.upper()} ---\n{payload.decode(charset, errors='ignore')}\n")
                except Exception as e:
                    body_parts.append(f"Error decoding {content_type}: {str(e)}\n")
    else:
        try:
            payload = msg.get_payload(decode=True)
            if isinstance(payload, bytes):
                if payload:
                    charset = msg.get_content_charset() or "utf-8"
                    body_parts.append(payload.decode(charset, errors="ignore"))
        except Exception as e:
            body_parts.append(f"Error decoding body: {str(e)}")

    return "\n".join(body_parts) if body_parts else "No body content found"


def save_attachments(msg: Message, attachments_dir: Path) -> List[dict]:
    """
    Docstring for save_attachments
    
    :return: saved_files
    :rtype: List[str]
    """
    saved_files = []

    if msg.is_multipart():
        for part in msg.walk():
            content_disposition = str(part.get("Content-Disposition", ""))

            # check if this part is an attachment
            if "attachment" in content_disposition or part.get_filename():
                filename = part.get_filename()

                if filename:
                    # Sanitize filename
                    filename = "".join(c for c in filename if c.isalnum() or c in (" ", ".", "_", "-"))
                    filepath = attachments_dir / filename

                    # Handle duplicate filenames
                    x = 1
                    original_filepath = filepath
                    while filepath.exists():
                        name, ext = os.path.splitext(original_filepath.name)
                        filepath = attachments_dir / f"{name}_{x}{ext}"
                        x += 1

                    try:
                        payload = part.get_payload(decode=True)
                        if isinstance(payload, bytes) and payload:
                            with open(filepath, "wb") as f:
                                f.write(payload)
                            # ---- ClamAV scan ----
                            clamav_result = scan_attachment_clamav(payload)
                            saved_files.append({
                                "filename": filepath.name,
                                "clamav": clamav_result,
                            })
                    except Exception as e:
                        print(f"Error saving attachment {filename}: {str(e)}")

    return saved_files


def scan_attachment_clamav(data: bytes) -> dict:
    """
    Scan a single attachment's bytes with ClamAV.
    Returns {"status": "clean"} or {"status": "infected", "threat": "<name>"}
    or {"status": "error", "detail": "<msg>"} if the daemon is unreachable.
    """
    try:
        cd = pyclamd.ClamdNetworkSocket(host=CLAMAV_HOST, port=3310)
        result = cd.scan_stream(data)
        if result is None:
            return {"status": "clean"}
        # pyclamd returns {"stream": ("FOUND", "<virus_name>")} on a hit
        status, threat = next(iter(result.values()))
        if status == "FOUND":
            return {"status": "infected", "threat": threat}
        return {"status": "clean"}
    except pyclamd.ConnectionError as e:
        return {"status": "error", "detail": str(e)}


### Diff-Check Comparison Helpers ###

# Headers for spoofing detection
_IDENTITY_HEADERS = ["From", "Reply-To", "Return-Path", "Sender"]

_AUTH_SYMBOL_PREFIXES = (
    "DKIM", "SPF", "DMARC", "ARC",
    "R_SPF", "R_DKIM", "R_DMARC",
    "FORGED", "SPOOF", "FROM_NEQ_ENVFROM",
    "MIME_FROM", "REPLYTO",
)

def _extract_domain(address: str) -> str:
    """
    Extract the domain from an email address or header value.
    """
    if not address:
        return ""
    # Handle "Display Name <user@email.com> formats
    match = re.search(r"@([\w.-]+)", address)
    return match.group(1).lower() if match else ""

def _extract_email_address(address: str) -> str:
    """
    Extract the email address from a header value.
    """
    if not address:
        return ""
    match = re.search(r"[\w.+-]+@[\w.-]+", address)
    return match.group(0).lower() if match else address.strip().lower()

def compare_identity_headers(suspicious: dict, legitimate: dict) -> dict:
    """
    Compare identity-related headers (From, Reply-To, Return-Path, Sender)
    between the suspicious and legitimate emails.
 
    Flags mismatches in both the full address and the domain, which is the
    primary indicator of a spoofing or impersonation attempt.
    """
    results = {}
    suspicious_summary = suspicious.get("summary", {})
    legitimate_summary = legitimate.get("summary", {})

    # Build quick lookup from the raw header files for headers not in summary
    suspicious_headers = _parse_header_file(suspicious)
    legitimate_headers = _parse_header_file(legitimate)

    for header in _IDENTITY_HEADERS:
        # Get values from summary (FROM/TO/DATE) or fall back to raw headers
        if header == "From":
            suspicious_value = suspicious_summary.get("from", "")
            legitimate_value = legitimate_summary.get("from", "")
        else:
            suspicious_value = suspicious_headers.get(header, "")
            legitimate_value = legitimate_headers.get(header, "")

        suspicious_address = _extract_email_address(suspicious_value)
        legitimate_address = _extract_email_address(legitimate_value)

        suspicious_domain = _extract_domain(suspicious_value)
        legitimate_domain = _extract_domain(legitimate_value)

        header_result = {
            "suspicious": suspicious_value,
            "legitimate": legitimate_value,
            "address_match": suspicious_address == legitimate_address,
            "domain_match": suspicious_domain == legitimate_domain,
            "suspicious_domain": suspicious_domain,
            "legitimate_domain": legitimate_domain
        }

        anomalies = []
        if legitimate_address and suspicious_address and not header_result["address_match"]:
            if header_result["domain_match"]:
                anomalies.append(f"Same sender domain but different addresses: {suspicious_address} vs {legitimate_address}.")
            else:
                anomalies.append(f"Different sender domain: {suspicious_domain} vs {legitimate_domain}.")
        elif legitimate_address and not suspicious_address:
            anomalies.append(f"{header} present in legitimate email but missing in suspicious email.")
        elif suspicious_address and not legitimate_address:
            anomalies.append(f"{header} present in suspicious email but missing in legitimate email.")

        header_result["anomalies"] = anomalies
        results[header] = header_result

        # Cross-header consistency: does From domain match Return-Path domain is suspicious email?
        suspicious_from_domain = _extract_domain(suspicious_summary.get("from", ""))
        suspicious_return_path_domain = _extract_domain(suspicious_headers.get("Return-Path", ""))
        if suspicious_from_domain and suspicious_return_path_domain and suspicious_from_domain != suspicious_return_path_domain:
            results["_cross_header_anomalies"] = [
                f"Suspicious email From domain ({suspicious_from_domain}) differs from Return-Path domain ({suspicious_return_path_domain}) - possible envelope spoofing."
            ]
        else:
            results["_cross_header_anomalies"] = []
        
        return results

def _parse_header_file(analysis: dict) -> dict:
    """
    Read the saved headers file and return a dict of header_name -> last_value.
    """
    headers_path = analysis.get("files_created", {}).get("headers", "")
    result = {}
    if headers_path and Path(headers_path).exists():
        try:
            text = Path(headers_path).read_text(encoding="utf-8", errors="ignore")
            for line in text.splitlines():
                if ": " in line:
                    key, _, value = line.partition(": ")
                    result[key.strip()] = value.strip()
        except Exception:
            pass
    return result

def compare_auth_results(suspicious: dict, legitimate: dict) -> dict:
    """
    Compare authentication related Rspamd symbols between both emails.

    Looks at DKIM, SPF, DMARC, ARC results and spoofing/forging indicators.
    """
    suspicious_symbols = suspicious.get("rspamd", {}).get("symbols", {})
    legitimate_symbols = legitimate.get("rspamd", {}).get("symbols", {})

    # Extract auth related symbols
    suspicious_auth = {k: v for k, v in suspicious_symbols.items() if any(k.startswith(p) for p in _AUTH_SYMBOL_PREFIXES)}
    legitimate_auth = {k: v for k, v in legitimate_symbols.items() if any(k.startswith(p) for p in _AUTH_SYMBOL_PREFIXES)}

    all_auth_keys = sorted(set(suspicious_auth) | set(legitimate_auth))

    comparison = {}
    anomalies = []

    for symbol in all_auth_keys:
        in_suspicious = symbol in suspicious_auth
        in_legitimate = symbol in legitimate_auth

        entry = {
            "in_suspicious": in_suspicious,
            "in_legitimate": in_legitimate,
        }

        if in_suspicious:
            entry["suspicious_score"] = suspicious_auth[symbol].get("score", 0)
            entry["suspicious_description"] = suspicious_auth[symbol].get("description", "")
        if in_legitimate:
            entry["legitimate_score"] = legitimate_auth[symbol].get("score", 0)
            entry["legitimate_description"] = legitimate_auth[symbol].get("description", "")

        # Flag symbols that only appear in the suspicious email with positive score

        if in_suspicious and not in_legitimate:
            score = suspicious_auth[symbol].get("score", 0)
            if score > 0:
                anomalies.append(
                    f"{symbol}, triggered only is suspicious email (score: {score}), {suspicious_auth[symbol].get('description', '')}."
                )

        # Flag auth passes in legitimate email that are absent/fail in suspicious email
        if in_legitimate and not in_suspicious:
            score = legitimate_auth[symbol].get("score", 0)
            if score < 0:
                anomalies.append(
                    f"{symbol} passed in legitimate email but absent in suspicious email."
                )
        
        comparison[symbol] = entry

    suspicious_score = suspicious.get("rspamd", {}).get("score")
    legitimate_score = legitimate.get("rspamd", {}).get("score")

    return {
        "symbols": comparison,
        "suspicious_total_score": suspicious_score,
        "legitimate_total_score": legitimate_score,
        "score_delta": round(suspicious_score - legitimate_score, 2) if suspicious_score is not None and legitimate_score is not None else None,
        "suspicious_action": suspicious.get("rspamd", {}).get("action"),
        "legitimate_action": legitimate.get("rspamd", {}).get("action"),
        "anomalies": anomalies,
    }

def compare_ip_geo(suspicious: dict, legitimate: dict) -> dict:
    """
    Compare sender IP addresses and their geolocation/network data
    between suspicious and legitimate emails.
    """
    suspicious_ips = suspicious.get("summary", {}).get("sender_ips", [])
    legitimate_ips = legitimate.get("summary", {}).get("sender_ips", [])

    suspicious_ip_set = {d.get("query", "") for d in suspicious_ips if isinstance(d, dict)}
    legitimate_ip_set = {d.get("query", "") for d in legitimate_ips if isinstance(d, dict)}

    shared_ips = suspicious_ip_set & legitimate_ip_set
    suspicious_only_ips = suspicious_ip_set - legitimate_ip_set
    legitimate_only_ips = legitimate_ip_set - suspicious_ip_set

    # Build lookup dicts
    suspicious_lookup = {d["query"]: d for d in suspicious_ips if isinstance(d, dict) and "query" in d}
    legitimate_lookup = {d["query"]: d for d in legitimate_ips if isinstance(d, dict) and "query" in d}

    anomalies = []

    # Compare geographic/network properties of IPs unique to suspicious email
    geo_comparison = []
    for ip in suspicious_only_ips:
        details = suspicious_lookup.get(ip, {})
        entry = {
            "ip": ip,
            "source": "suspicious_only",
            "country": details.get("country"),
            "region": details.get("regionName"),
            "city": details.get("city"),
            "isp": details.get("isp"),
            "org": details.get("org"),
            "as": details.get("as"),
            "reverse": details.get("reverse"),
            "proxy": details.get("proxy"),
            "hosting": details.get("hosting"),
        }
        geo_comparison.append(entry)

        # Flag proxy/hosting/VPN IPs in suspicious email
        if details.get("proxy"):
            anomalies.append(f"Suspicious IP ({ip}) is flagged as a proxy/VPN.")
        if details.get("hosting"):
            anomalies.append(f"Suspicious IP ({ip}) originated from a hosting provider")

    for ip in legitimate_only_ips:
        details = legitimate_lookup.get(ip, {})
        geo_comparison.append({
            "ip": ip,
            "source": "legitimate_only",
            "country": details.get("country"),
            "region": details.get("regionName"),
            "city": details.get("city"),
            "isp": details.get("isp"),
            "org": details.get("org"),
            "as": details.get("as"),
            "reverse": details.get("reverse"),
            "proxy": details.get("proxy"),
            "hosting": details.get("hosting"),
        })

    # Country / ASN Divergence
    suspicious_countries = {d.get("country") for d in suspicious_ips if isinstance(d, dict) and d.get("country")}
    legitimate_countries = {d.get("country") for d in legitimate_ips if isinstance(d, dict) and d.get("country")}
    suspicious_asns = {d.get("as") for d in suspicious_ips if isinstance(d, dict) and d.get("as")}
    legitimate_asns = {d.get("as") for d in legitimate_ips if isinstance(d, dict) and d.get("as")}

    if suspicious_countries and legitimate_countries and not suspicious_countries & legitimate_countries:
        anomalies.append(
            f"Complete country mismatch: suspicious from {sorted(suspicious_countries)}, legitimate from {sorted(legitimate_countries)}"
        )

    if suspicious_asns and legitimate_asns and not suspicious_asns & legitimate_asns:
        anomalies.append(
            f"No shared ASN between suspicious ({sorted(suspicious_asns)}) and legitimate ({sorted(legitimate_asns)})."
        )

    return {
        "shared_ips": sorted(shared_ips),
        "suspicious_only_ips": sorted(suspicious_only_ips),
        "legitimate_only_ips": sorted(legitimate_only_ips),
        "ip_overlap": len(shared_ips) > 0,
        "geo_details": geo_comparison,
        "suspicious_countries": sorted(suspicious_countries),
        "legitimate_countries": sorted(legitimate_countries),
        "anomalies": anomalies,
    }

def compare_body_similarity(suspicious: dict, legitimate: dict) -> dict:
    """
    Lightweight body similarity check using SequenceMatcher.
    This is secondary to the header/auth/IP checks but can surface
    template cloning attempts.
    """
    suspicious_body_path = suspicious.get("files_created", {}).get("body", "")
    legitimate_body_path = legitimate.get("files_created", {}).get("body", "")

    suspicious_body = ""
    legitimate_body = ""

    if suspicious_body_path and Path(suspicious_body_path).exists():
        suspicious_body = Path(suspicious_body_path).read_text(encoding="utf-8", errors="ignore")
    if legitimate_body_path and Path(legitimate_body_path).exists():
        legitimate_body = Path(legitimate_body_path).read_text(encoding="utf-8", errors="ignore")
    
    if not suspicious_body or not legitimate_body:
        return {
            "similarity_ratio": None,
            "note": "One or both emails bodies could not be read.",
        }
    
    ratio = SequenceMatcher(None, suspicious_body, legitimate_body).ratio()

    interpretation = "low"
    if ratio >= 0.9:
        interpretation = "very_high"
    elif ratio >= 0.7:
        interpretation = "high"
    elif ratio >= 0.4:
        interpretation = "moderate"

    return {
        "similarity_ratio": round(ratio, 4),
        "interpretation": interpretation,
        "note": (
            "Very high similarity may indicate the suspicious email cloned "
            "the legitimate email's template or content."
            if ratio >= 0.7 else None
        )
    }

def compute_risk_assessment(
    header_diff: dict,
    auth_diff: dict,
    ip_diff: dict,
    body_sim: dict,
) -> dict:
    """
    Produce a summary risk assessment based on all comparison axes.
    Collects all anomalies and assigns a simple risk level.
    """
    all_anomalies = []

    # Header anomalies
    for header_name, data in header_diff.items():
        if header_name.startswith("_"):
            all_anomalies.extend(data)
        elif isinstance(data, dict):
            all_anomalies.extend(data.get("anomalies", []))

    # Auth anomalies
    all_anomalies.extend(auth_diff.get("anomalies", []))

    # IP/Geo anomalies
    all_anomalies.extend(ip_diff.get("anomalies", []))

    # Body cloning signal
    sim_ratio = body_sim.get("similarity_ratio")
    if sim_ratio is not None and sim_ratio >= 0.7:
        all_anomalies.append(f"Email body is {round(sim_ratio * 100, 1)}% similar to the legitimate email - possible template cloning.")

    # TODO Simple risk score 
    risk_score = len(all_anomalies)

    # Boost score for strong signals
    if not ip_diff.get("ip_overlap", True):
        risk_score += 2
    
    score_delta = auth_diff.get("score_delta")
    if score_delta is not None and score_delta > 5:
        risk_score += 3
    
    if risk_score == 0:
        level = "low"
        verdict = "No significant differences detected between emails."
    elif risk_score <= 3:
        level = "medium"
        verdict = "Some differences detected. Proceed with caution."
    elif risk_score <=6:
        level = "high"
        verdict = "Multiple anomalies detected. This email shows signs of spoofing an impersonation."
    else:
        level = "critical"
        verdict = "Strong indicators of spoofing or impersonation detected. This email is most likely fraudulent."

    return {
        "risk_level": level,
        "risk_score": risk_score,
        "verdict": verdict,
        "total_anomalies": len(all_anomalies),
        "all_anomalies": all_anomalies,
    }

def load_analysis(email_id: str) -> dict:
    """
    Load a previously-persisted analysis JSON by email_id.
    Raises HTTPException 404 if not found.
    """
    analysis_path = EMAIL_ANALYSIS_DIR / email_id / f"analysis-{email_id}.json"
    if not analysis_path.exists():
        raise HTTPException(
            status_code=404,
            detail=f"Analysis not found for email '{email_id}'."
        )
    try:
        return json.loads(analysis_path.read_text(encoding="utf-8"))
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to read analysis for email '{email_id}'."
        )


@app.post("/parse-email")
async def parse_email(file: UploadFile = File(...)):
    if not file.filename or not file.filename.endswith(".eml"):
        raise HTTPException(status_code=400, detail="File must be a .eml file")
    
    try:
        # read the email file
        content = await file.read()

        # parse the email
        msg = BytesParser(policy=policy.default).parsebytes(content)
        
        # generate unique email ID
        email_id = generate_email_id()

        # create main dir under persistent output path
        EMAIL_ANALYSIS_DIR.mkdir(parents=True, exist_ok=True)
        main_dir = EMAIL_ANALYSIS_DIR / f"{email_id}"
        main_dir.mkdir(parents=True, exist_ok=True)

        # create attachments dir
        attachments_dir = main_dir / "attachments"
        attachments_dir.mkdir(exist_ok=True)

        # Extract and save headers
        headers = extract_headers(msg)
        sender_ips = extract_sender_ips(msg)
        sender_ip_details = []
        if sender_ips:
            sender_ip_details = await asyncio.gather(
                *(analyze_sender_ip(ip) for ip in sender_ips)
            )

            # Always return IP intelligence for all sender IPs, but only map one IP:
            # the first result that has reverse DNS and coordinates.
            for details in sender_ip_details:
                details["map_url"] = None

            map_target_index = None
            for i, details in enumerate(sender_ip_details):
                reverse_dns = str(details.get("reverse") or "").strip()
                lat = details.get("lat")
                lon = details.get("lon")
                query_ip = details.get("query")

                if reverse_dns and lat is not None and lon is not None and query_ip:
                    map_target_index = i
                    break

            if map_target_index is not None:
                target = sender_ip_details[map_target_index]
                map_path = await get_map_for_ip(
                    target["query"],
                    target["lat"],
                    target["lon"],
                    email_id,
                    main_dir,
                )
                if map_path:
                    # Convert: /data/email-analysis/email-analysis-123/map-123.png
                    # To: /analysis-results/email-analysis-123/map-123.png
                    web_url = f"/analysis-results/{Path(map_path).relative_to(EMAIL_ANALYSIS_DIR)}"
                    sender_ip_details[map_target_index]["map_url"] = web_url

        headers_file = main_dir / f"headers-{email_id}.txt"
        with open(headers_file, "w", encoding="utf-8") as f:
            f.write(headers)

        # extract and save body
        body = extract_body(msg)
        body_file = main_dir / f"body-{email_id}.txt"
        with open(body_file, "w", encoding="utf-8") as f:
            f.write(body)
        
        # extract and save attachments
        saved_attachments = save_attachments(msg, attachments_dir)

        # scan with rspamd
        try:
            rspamd_raw = await scan_with_rspamd(content)
            rspamd_parsed = parse_rspamd_response(rspamd_raw)
        except Exception as e:
            rspamd_parsed = {"error": str(e)}

        # Build clamav summary from results already collected in save_attachments()
        clamav_results = {
            a["filename"]: a["clamav"]
            for a in saved_attachments
        }

        # response
        response = {
            "status": "success",
            "email_id": email_id,
            "output_directory": str(main_dir),
            "files_created": {
                "headers": str(headers_file),
                "body": str(body_file),
                "attachments" : saved_attachments,
            },
            "summary": {
                "subject": msg.get("Subject", "No subject"),
                "from": msg.get("From", "Unknown"),
                "to": msg.get("To", "Unknown"),
                "date": msg.get("Date", "Unknown"),
                "sender_ips": sender_ip_details,
                "attachment_count": len(saved_attachments),
            },
            "rspamd": rspamd_parsed,
            "clamav": clamav_results,  # Add ClamAV results to response
        }

        analysis_file = main_dir / f"analysis-{email_id}.json"
        analysis_file.write_text(
            json.dumps(response, indent=2, default=str),
            encoding="utf-8"
        )

        return JSONResponse(content=response)
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error parsing email: {str(e)}")


@app.get("/")
def read_root():
    return {
        "statusCode": 0,
        "message": "Email parser API is running"
    }

