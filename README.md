# Minimal ALTCHA Test

A simple FastAPI app implementing an ALTCHA-like proof-of-work CAPTCHA for form protection. Deployable on Render.

## Features
- Generates challenges with adjustable difficulty.
- Client-side JS solves the PoW (brute-force nonce search).
- Server verifies submission.
- Simple form demo.

## Local Development
```bash
pip install -r requirements.txt
uvicorn main:app --reload