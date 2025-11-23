import os
import json
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, Request, HTTPException
import stripe
import requests

# FastAPI app
app = FastAPI()

# Stripe config
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")

# Jarvas config
JARVAS_BASE_URL = os.getenv("JARVAS_BASE_URL", "https://jarvas-memory-api.onrender.com")
JARVAS_USER_ID = os.getenv("JARVAS_USER_ID", "zach")
JARVAS_API_KEY = os.getenv("JARVAS_API_KEY")  # <-- fixed typo


def _jarvas_headers() -> Dict[str, str]:
    """Include API key for Jarvas Memory."""
    headers: Dict[str, str] = {}
    if JARVAS_API_KEY:
        headers["x-api-key"] = JARVAS_API_KEY
    return headers


def _load_training_clients() -> List[Dict[str, Any]]:
    """Get the current training_clients array from Jarvas memory."""
    try:
        resp = requests.get(
            f"{JARVAS_BASE_URL}/get_memory",
            params={"user_id": JARVAS_USER_ID},
            headers=_jarvas_headers(),
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        print("Error calling get_memory:", e)
        return []

    memories = data.get("memories", [])
    tc_entry = next((m for m in memories if m.get("key") == "training_clients"), None)
    if not tc_entry:
        return []

    value = tc_entry.get("value")
    if not value:
        return []

    try:
        arr = json.loads(value)
        if isinstance(arr, list):
            return arr
        # if somehow it's a single object, wrap it
        if isinstance(arr, dict):
            return [arr]
    except Exception as e:
        print("Error parsing training_clients JSON:", e)

    return []


def _save_training_clients(clients: List[Dict[str, Any]]) -> None:
    """Save the full training_clients array back to Jarvas."""
    payload = {
        "user_id": JARVAS_USER_ID,
        "key": "training_clients",
        "value": json.dumps(clients),
    }
    try:
        resp = requests.post(
            f"{JARVAS_BASE_URL}/save_memory",
            json=payload,
            headers=_jarvas_headers(),
            timeout=10,
        )
        resp.raise_for_status()
    except Exception as e:
        print("Error saving training_clients to Jarvas:", e)


def update_training_client_from_stripe(
    customer_email: Optional[str],
    customer_name: Optional[str],
    tier: str,
    status: str,
) -> None:
    """
    Upsert a client inside the training_clients array based on email.
    """
    if not customer_email:
        print("No customer_email in Stripe event; skipping training_clients update.")
        return

    clients = _load_training_clients()

    # Try to find existing client by email
    client = next((c for c in clients if c.get("email") == customer_email), None)

    if client is None:
        client = {
            "id": f"stripe_{customer_email}",
            "name": customer_name,
            "email": customer_email,
        }
        clients.append(client)

    # Update fields
    client["coaching_tier"] = tier
    client["billing_status"] = status  # e.g. active / past_due / canceled
    client["source"] = "stripe_webhook"

    _save_training_clients(clients)
    print(f"Updated training_clients for {customer_email} (tier={tier}, status={status})")


@app.get("/")
async def root():
    return {"status": "ok", "service": "zachfit-backend"}


@app.post("/stripe-webhook")
async def stripe_webhook(request: Request):
    """Endpoint Stripe calls for subscription events."""
    payload = await request.body()
    sig_header = request.headers.get("Stripe-Signature")

    if WEBHOOK_SECRET is None:
        raise HTTPException(status_code=500, detail="Webhook secret not configured")

    try:
        event = stripe.Webhook.construct_event(
            payload=payload,
            sig_header=sig_header,
            secret=WEBHOOK_SECRET,
        )
    except ValueError:
        # Invalid payload
        raise HTTPException(status_code=400, detail="Invalid payload")
    except stripe.error.SignatureVerificationError:
        # Invalid signature
        raise HTTPException(status_code=400, detail="Invalid signature")

    event_type = event["type"]
    data = event["data"]["object"]

    print("Received Stripe event:", event_type)

    if event_type == "checkout.session.completed":
        customer_email = data.get("customer_details", {}).get("email")
        customer_name = data.get("customer_details", {}).get("name")

        # You can decode tier from price/product later; for now mark unknown+active
        update_training_client_from_stripe(
            customer_email=customer_email,
            customer_name=customer_name,
            tier="unknown",
            status="active",
        )

    elif event_type in (
        "customer.subscription.updated",
        "customer.subscription.deleted",
        "invoice.payment_failed",
    ):
        # TODO: later we can parse real status + email here and call update_training_client_from_stripe
        customer_email = data.get("customer_email")
        print("Subscription-related event for customer:", customer_email)

    return {"received": True}
