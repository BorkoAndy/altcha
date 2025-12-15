from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles  # If you add static files later
import os
import secrets
import hashlib
import hmac
import base64
import json
from datetime import datetime

app = FastAPI(
    title="Minimal ALTCHA Test",
    description="A simple FastAPI app implementing an ALTCHA-like proof-of-work CAPTCHA for form protection",
    version="0.1.0"
)

# Set up templates
templates = Jinja2Templates(directory="templates")

# HMAC key - In production, set as env var: os.getenv("ALTCHA_HMAC_KEY")
# For testing, generate a random one (but it won't persist across restarts)
HMAC_KEY = os.getenv("ALTCHA_HMAC_KEY", secrets.token_bytes(32))

# Configuration
MAXNUMBER = 100000  # Adjust for difficulty: higher = harder (more work)

@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/challenge")
async def get_challenge():
    # Generate random salt (at least 10 chars)
    salt = secrets.token_hex(12)  # 24 chars hex
    
    # Optional: Add expiration or other params to salt
    expires = int(datetime.utcnow().timestamp()) + 300  # 5 min expiry
    salt += f"?expires={expires}"
    
    # Generate secret number
    secret_number = secrets.randbelow(MAXNUMBER + 1)  # 0 to MAXNUMBER
    
    # Compute challenge: SHA-256(salt + str(secret_number)).hex()
    data_to_hash = (salt + str(secret_number)).encode("utf-8")
    challenge = hashlib.sha256(data_to_hash).hexdigest()
    
    # Compute signature: HMAC-SHA-256(challenge, HMAC_KEY).hex()
    signature = hmac.new(HMAC_KEY, challenge.encode("utf-8"), hashlib.sha256).hexdigest()
    
    # Return challenge payload
    return {
        "algorithm": "SHA-256",
        "challenge": challenge,
        "maxnumber": MAXNUMBER,
        "salt": salt,
        "signature": signature
    }

@app.post("/verify")
async def verify(payload: str = Form(...)):
    try:
        # Decode base64 payload
        decoded = base64.b64decode(payload).decode("utf-8")
        data = json.loads(decoded)
        
        # Check required fields
        required = {"algorithm", "challenge", "number", "salt", "signature"}
        if not required.issubset(data.keys()):
            raise ValueError("Missing fields")
        
        # Verify algorithm
        if data["algorithm"] != "SHA-256":
            raise ValueError("Invalid algorithm")
        
        # Verify challenge: SHA-256(salt + str(number)) == challenge
        computed_challenge = hashlib.sha256((data["salt"] + str(data["number"])).encode("utf-8")).hexdigest()
        if computed_challenge != data["challenge"]:
            raise ValueError("Invalid challenge")
        
        # Verify signature: HMAC-SHA-256(challenge, HMAC_KEY) == signature
        computed_signature = hmac.new(HMAC_KEY, data["challenge"].encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(computed_signature, data["signature"]):
            raise ValueError("Invalid signature")
        
        # Optional: Check expiration if in salt
        if "?expires=" in data["salt"]:
            expires_str = data["salt"].split("?expires=")[1].split("&")[0]
            expires = int(expires_str)
            if datetime.utcnow().timestamp() > expires:
                raise ValueError("Expired challenge")
        
        return {"verified": True}
    
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/submit")
async def submit_form(name: str = Form(...), altcha: str = Form(...)):
    # First, verify ALTCHA
    verify_response = await verify(altcha)
    if not verify_response.get("verified"):
        raise HTTPException(status_code=400, detail="ALTCHA verification failed")
    
    # Process form (simple echo)
    return {"message": f"Form submitted successfully! Name: {name}"}

# For local testing
if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)