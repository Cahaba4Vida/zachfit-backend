import os
import json
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


def update_training_client_from_stripe(customer_email: str, customer_name: str | None, tier: str, status: str):
    """
    Minimal example: calls Jarvas /save_memory to upsert a training_clients entry.
    You can make this smarter later; main goal now is just: webhook path exists and works.
    """
    if not customer_email:
        return

    # Build a simple payload Jarvas can handle. Adjust to match your Jarvas API spec.
    payload = {
        "user_id": JARVAS_USER_ID,
        "key": "training_clients",
        "value": json.dumps({
            "source": "stripe_webhook",
            "customer_email": customer_email,
            "customer_name": customer_name,
            "coaching_tier": tier,
            "billing_status": status,
        }),
    }

    try:
        requests.post(f"{JARVAS_BASE_URL}/save_memory", json=payload, timeout=5)
    except Exception as e:
        # Don't crash webhook if Jarvas is down; just log.
        print("Error updating Jarvas training_clients:", e)


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

    # Basic handling – you can expand this later
    if event_type == "checkout.session.completed":
        customer_email = data.get("customer_details", {}).get("email")
        customer_name = data.get("customer_details", {}).get("name")
        # Decide tier from price/product if you want; for now, just mark active
        update_training_client_from_stripe(customer_email, customer_name, tier="unknown", status="active")

    elif event_type in ("customer.subscription.updated", "customer.subscription.deleted", "invoice.payment_failed"):
        # You can parse subscription status and update Jarvas
        customer_email = data.get("customer_email") or data.get("customer", None)
        # Here we just log, but you can call update_training_client_from_stripe
        print("Subscription-related event for customer:", customer_email)

    return {"received": True}
