from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
import os
import secrets
import hashlib
import hmac
import base64
import json
from datetime import datetime

app = FastAPI(
    title="ALTCHA Test (No Env Vars)",
    description="Simple self-hosted ALTCHA-like PoW CAPTCHA – testing mode",
    version="0.1.0"
)

templates = Jinja2Templates(directory="templates")

import os

# Require HMAC key from env var (no fallback in production)
HMAC_KEY_HEX = os.getenv("ALTCHA_HMAC_KEY")
if not HMAC_KEY_HEX:
    raise ValueError("ALTCHA_HMAC_KEY environment variable must be set!")

# Convert hex string to bytes
try:
    HMAC_KEY = bytes.fromhex(HMAC_KEY_HEX)
except ValueError:
    raise ValueError("ALTCHA_HMAC_KEY must be a valid hex string")

# Config (hardcoded for simple testing)
MAXNUMBER = 100000  # ~0.1–0.5 sec solve time on modern browsers
CHALLENGE_EXPIRY_SECONDS = 300  # 5 minutes

@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/challenge")
async def get_challenge():
    salt = secrets.token_hex(12)
    expires = int(datetime.utcnow().timestamp()) + CHALLENGE_EXPIRY_SECONDS
    salt += f"?expires={expires}"

    secret_number = secrets.randbelow(MAXNUMBER + 1)
    data_to_hash = (salt + str(secret_number)).encode("utf-8")
    challenge = hashlib.sha256(data_to_hash).hexdigest()

    signature = hmac.new(HMAC_KEY, challenge.encode("utf-8"), hashlib.sha256).hexdigest()

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
        decoded = base64.b64decode(payload).decode("utf-8")
        data = json.loads(decoded)

        required = {"algorithm", "challenge", "number", "salt", "signature"}
        if not required.issubset(data.keys()):
            raise ValueError("Missing fields")

        if data["algorithm"] != "SHA-256":
            raise ValueError("Invalid algorithm")

        computed_challenge = hashlib.sha256((data["salt"] + str(data["number"])).encode("utf-8")).hexdigest()
        if computed_challenge != data["challenge"]:
            raise ValueError("Invalid challenge")

        computed_signature = hmac.new(HMAC_KEY, data["challenge"].encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(computed_signature, data["signature"]):
            raise ValueError("Invalid signature")

        if "?expires=" in data["salt"]:
            expires_str = data["salt"].split("?expires=")[1].split("&")[0]
            if datetime.utcnow().timestamp() > int(expires_str):
                raise ValueError("Challenge expired")

        return {"verified": True}

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Verification failed: {str(e)}")

@app.post("/submit")
async def submit_form(name: str = Form(...), altcha: str = Form(...)):
    await verify(altcha)  # Will raise if invalid
    return {"message": f"Success! Hello, {name}! Your form was protected by ALTCHA. 🎉"}

# Local run support
if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)