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

        return JSONResponse(content=response)
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error parsing email: {str(e)}")


@app.get("/")
def read_root():
    return {
        "statusCode": 0,
        "message": "Email parser API is running"
    }

