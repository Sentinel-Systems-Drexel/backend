from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from email import policy
from email.parser import BytesParser
from email.message import Message, EmailMessage
import os
import uuid
from pathlib import Path
from typing import List


app = FastAPI(title="Python Orch Layer", version="0.0.1")

# Initialize Ipinfo Lite handler with API token from environment variable
if IPINFO_TOKEN:
    try:
        import ipinfo
        ipinfo_handler = ipinfo.getHandlerLite(access_token=IPINFO_TOKEN)
    except ImportError as e:
        ipinfo_error = str(e)

# Initialize CORS middleware to allow requests from any origin (for testing purposes)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def generate_email_id() -> str:
    '''
    Generate unique email ID
    
    :return: email_id
    :rtype: str
    '''
    return str(uuid.uuid4())[:8]


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
                    # If it's a 2002: address, this extracts the embedded IPv4
                    if isinstance(ip_obj, IPv6Address) and ip_obj.sixtofour:
                        ip_obj = ip_obj.sixtofour
                    
                    # 3. Handle IPv4-Mapped IPv6 (::ffff:192.168.1.1)
                    if isinstance(ip_obj, IPv6Address) and ip_obj.ipv4_mapped:
                        ip_obj = ip_obj.ipv4_mapped

                    # 4. Bogon Filtering (The API Saver)
                    # This drops: 127.0.0.1, 10.x.x.x, 192.168.x.x, 169.254.x.x, etc.
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
    if not IPINFO_TOKEN:
        return {"ip": ip, "error": "IPINFO_TOKEN is not configured"}

    if ipinfo_handler is None:
        detail = "ipinfo is not installed"
        if ipinfo_error:
            detail = f"{detail}: {ipinfo_error}"
        return {"ip": ip, "error": detail}

    try:
        response = await asyncio.to_thread(ipinfo_handler.getDetails, ip)
        details = response.all if isinstance(response.all, dict) else {}
        if "ip" not in details:
            details["ip"] = ip
        return details
    except Exception as e:
        return {"ip": ip, "error": str(e)}

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


def save_attachments(msg: Message, attachments_dir: Path) -> List[str]:
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
                        with open(filepath, 'wb') as f:
                            payload = part.get_payload(decode=True)
                            if isinstance(payload, bytes):
                                if payload:
                                    f.write(payload)
                                    saved_files.append(str(filepath.name))
                    except Exception as e:
                        print(f"Error saving attachment {filename}: {str(e)}")

    return saved_files


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
        main_dir = EMAIL_ANALYSIS_DIR / f"email-analysis-{email_id}"
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
                "subject": msg.get("Subject, No subject"),
                "from": msg.get("From", "Unknown"),
                "to": msg.get("To", "Unknown"),
                "date": msg.get("Date", "Unknown"),
                "attachment_count": len(saved_attachments),
            }
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

