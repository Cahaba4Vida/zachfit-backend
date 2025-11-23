import os
import json
from datetime import datetime

from fastapi import FastAPI, Request, HTTPException
import stripe
import requests

# -----------------------------
# FastAPI app
# -----------------------------
app = FastAPI()

# -----------------------------
# Stripe config
# -----------------------------
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")

# Price IDs (from Stripe dashboard env vars)
STRIPE_LITE_PRICE_ID = os.getenv("STRIPE_LITE_PRICE_ID")
STRIPE_STANDARD_PRICE_ID = os.getenv("STRIPE_STANDARD_PRICE_ID")

# -----------------------------
# Jarvas config
# -----------------------------
JARVAS_BASE_URL = os.getenv(
    "JARVAS_BASE_URL",
    "https://jarvas-memory-api.onrender.com",
)
JARVAS_USER_ID = os.getenv("JARVAS_USER_ID", "zach")
JARVAS_API_KEY = os.getenv("JARVAS_API_KEY")


def _slugify_name(name: str | None) -> str:
    if not name:
        return "client"
    return (
        name.strip()
        .lower()
        .replace(" ", "_")
        .replace("@", "_")
        .replace(".", "_")
    )


def _iso_now() -> str:
    return datetime.utcnow().isoformat() + "Z"


# -----------------------------
# Jarvas helpers
# -----------------------------
def fetch_training_clients() -> list[dict]:
    """
    Get the current training_clients array from Jarvas memory.
    Returns [] if not found or if anything looks broken.
    """
    try:
        headers = {}
        if JARVAS_API_KEY:
            headers["x-api-key"] = JARVAS_API_KEY

        resp = requests.get(
            f"{JARVAS_BASE_URL}/get_memory",
            params={"user_id": JARVAS_USER_ID},
            headers=headers,
            timeout=5,
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        print("Error calling get_memory:", e)
        return []

    memories = data.get("memories", [])
    for mem in memories:
        if mem.get("key") == "training_clients":
            raw = mem.get("value", "[]")
            try:
                arr = json.loads(raw)
                if isinstance(arr, list):
                    return arr
            except Exception as e:
                print("Error parsing training_clients JSON:", e)
                return []
    return []


def save_training_clients(clients: list[dict]) -> None:
    """
    Save the full training_clients array back into Jarvas.
    """
    payload = {
        "user_id": JARVAS_USER_ID,
        "key": "training_clients",
        "value": json.dumps(clients),
    }

    headers = {}
    if JARVAS_API_KEY:
        headers["x-api-key"] = JARVAS_API_KEY

    try:
        resp = requests.post(
            f"{JARVAS_BASE_URL}/save_memory",
            json=payload,
            headers=headers,
            timeout=5,
        )
        resp.raise_for_status()
        print("Saved training_clients to Jarvas. Status:", resp.status_code)
    except Exception as e:
        print("Error saving training_clients:", e)


def infer_tier_from_price(price_id: str | None) -> str:
    """
    Map Stripe price ID -> coaching_tier label.
    """
    if not price_id:
        return "unknown"

    if STRIPE_LITE_PRICE_ID and price_id == STRIPE_LITE_PRICE_ID:
        return "ai_only"

    if STRIPE_STANDARD_PRICE_ID and price_id == STRIPE_STANDARD_PRICE_ID:
        return "standard"

    return "unknown"


def update_training_client_from_stripe(
    customer_email: str | None,
    customer_name: str | None,
    price_id: str | None,
    status: str,
) -> None:
    """
    Upsert a client into training_clients based on Stripe subscription/checkout.
    """
    if not customer_email:
        print("No customer_email; skipping training_clients update.")
        return

    coaching_tier = infer_tier_from_price(price_id)
    clients = fetch_training_clients()
    email_lower = customer_email.lower()

    # Try to find existing client by email
    existing = None
    for c in clients:
        if c.get("email", "").lower() == email_lower:
            existing = c
            break

    if existing:
        print("Updating existing training client from Stripe:", customer_email)
        existing["name"] = existing.get("name") or customer_name
        existing["email"] = customer_email
        existing["coaching_tier"] = coaching_tier
        existing["billing_status"] = status
        existing["billing_last_updated"] = _iso_now()
        existing.setdefault("source", "stripe")
    else:
        print("Creating new training client from Stripe:", customer_email)
        slug = _slugify_name(customer_name or customer_email)
        year = datetime.utcnow().year
        new_client = {
            "id": f"train_{slug}_{year}",
            "name": customer_name,
            "email": customer_email,
            "status": "active",
            "coaching_tier": coaching_tier,
            "billing_status": status,
            "billing_last_updated": _iso_now(),
            "source": "stripe",
        }
        clients.append(new_client)

    save_training_clients(clients)


# -----------------------------
# FastAPI routes
# -----------------------------
@app.get("/")
async def root():
    return {"status": "ok", "service": "zachfit-backend"}


@app.post("/stripe-webhook")
async def stripe_webhook(request: Request):
    """
    Endpoint Stripe calls for subscription / checkout events.
    """
    payload = await request.body()
    sig_header = request.headers.get("Stripe-Signature")

    if not WEBHOOK_SECRET:
        raise HTTPException(status_code=500, detail="Webhook secret not configured")

    try:
        event = stripe.Webhook.construct_event(
            payload=payload,
            sig_header=sig_header,
            secret=WEBHOOK_SECRET,
        )
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid payload")
    except stripe.error.SignatureVerificationError:
        raise HTTPException(status_code=400, detail="Invalid signature")

    event_type = event["type"]
    obj = event["data"]["object"]

    print("Received Stripe event:", event_type)

    # ------ checkout.session.completed ------
    if event_type == "checkout.session.completed":
        customer_email = (
            obj.get("customer_details", {}) or {}
        ).get("email") or obj.get("customer_email")
        customer_name = (
            obj.get("customer_details", {}) or {}
        ).get("name")

        # Try to pull a price_id from the session
        price_id = None
        subscription = obj.get("subscription")
        if isinstance(subscription, dict):
            # In some webhook types you might get expanded subscription
            items = subscription.get("items", {}).get("data", [])
            if items:
                price_id = items[0].get("price", {}).get("id")
        elif isinstance(subscription, str):
            try:
                sub = stripe.Subscription.retrieve(subscription)
                items = sub.get("items", {}).get("data", [])
                if items:
                    price_id = items[0].get("price", {}).get("id")
            except Exception as e:
                print("Error retrieving subscription:", e)

        update_training_client_from_stripe(
            customer_email=customer_email,
            customer_name=customer_name,
            price_id=price_id,
            status="active",
        )

    # ------ subscription / billing updates ------
    elif event_type in (
        "customer.subscription.updated",
        "customer.subscription.deleted",
        "invoice.payment_failed",
    ):
        # These events all have a subscription object
        customer_email = obj.get("customer_email")
        customer_name = obj.get("customer_name")

        price_id = None
        items = obj.get("items", {}).get("data", [])
        if items:
            price_id = items[0].get("price", {}).get("id")

        billing_status = obj.get("status") or "unknown"

        update_training_client_from_stripe(
            customer_email=customer_email,
            customer_name=customer_name,
            price_id=price_id,
            status=billing_status,
        )

    # Always return 200 so Stripe is happy unless we explicitly error out
    return {"received": True}
