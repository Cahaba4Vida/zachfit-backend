import os
import json
from datetime import datetime, timezone

import requests
import stripe
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from dotenv import load_dotenv

# Load .env for local dev (Render will use its own env vars)
load_dotenv()

# ----- Stripe config -----
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")

LITE_PRICE_ID = os.getenv("STRIPE_LITE_PRICE_ID")
STANDARD_PRICE_ID = os.getenv("STRIPE_STANDARD_PRICE_ID")

# ----- Jarvas Memory API config -----
JARVAS_BASE_URL = os.getenv("JARVAS_BASE_URL", "https://jarvas-memory-api.onrender.com")
JARVAS_USER_ID = os.getenv("JARVAS_USER_ID", "zach")

app = FastAPI()   # ← THIS must be here, at the left margin
