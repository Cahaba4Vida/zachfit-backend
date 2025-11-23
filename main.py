import os
import json
from datetime import datetime

from fastapi import FastAPI, Request, HTTPException
import stripe
import requests
from dotenv import load_dotenv

# Load .env locally; on Render you set env vars in the dashboard
load_dotenv()

app = FastAPI()

# Stripe config
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")

LITE_PRICE_ID = os.getenv("STRIPE_LITE_PRICE_ID")
STANDARD_PRICE_ID = os.getenv("STRIPE_STANDARD_PRICE_ID")

# Jarvas config
JARVAS_BASE_URL = os.getenv("JARVAS_BASE_URL", "https://jarvas-memory-api.onrender.com")
JARVAS_USER_ID = os.getenv("JARVAS_USER_ID", "zach")


# ---------- Helpers ----------

def slugify(text: str) -> str:
    text = (text or "").strip().lower()
    if not text:
        return "client"
    out = []
    for c in text:
        if c.isalnum():
            out.append(c)
        elif c in (" ", "-", "_"):
            out.append("-")
    slug = "".join(out).strip("-")
    return slug or "client"


def map_price_to_tier(price_id: str | None) -> str:
    """
    Map Stripe price ID -> coaching tier.
    Defaults to 'unknown' if we don't recognize it.
    """
    if not price_id:
        return "unknown"
    if LITE_PRICE_ID and price_id == LITE_PRICE_ID:
        return "ai_only"
    if STANDARD_PRICE_ID and price_id == STANDARD_PRICE_ID:
        return "standard"
    return "unknown"


def load_training_clients() -> list[dict]:
    """
    Pull training_clients from Jarvas memory.
    Returns a Python list (may be empty).
    """
    try:
        resp = requests.get(
            f"{JARVAS_BASE_URL}/get_memory",
            params={"user_id": JARVAS_USER_ID},
            timeout=8,
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        print("Error calling get_memory:", e)
        return []

    memories = data.get("memories", [])
    value = None
    for m in memories:
        if m.get("key") == "training_clients":
            value = m.get("value")
            break

    if not value:
        return []

    try:
        arr = json.loads(value)
        if isinstance(arr, list):
            return arr
        else:
            print("training_clients value was not a list, resetting to [] in working memory")
            return []
    except Exception as e:
        print("Error parsing training_clients JSON:", e)
        return []


def save_training_clients(clients: list[dict]) -> None:
    """
    Save the full training_clients list back into Jarvas.
    """
    try:
        payload = {
            "user_id": JARVAS_USER_ID,
            "key": "training_clients",
            "value": json.dumps(clients),
        }
        resp = requests.post(f"{JARVAS_BASE_URL}/save_memory", json=payload, timeout=8)
        resp.raise_for_status()
    except Exception as e:
        print("Error calling save_memory for training_clients:", e)


def update_training_client_from_stripe(
    customer_email: str | None,
    customer_name: str | None,
    tier: str,
    billing_status: str,
):
    """
    Merge Stripe subscription info into training_clients.

    - Match by email first.
    - If no email match, try name.
    - If no existing client, create a new barebones client entry.
    - Update coaching_tier + billing_status + status.
    """
    if not customer_email and not customer_name:
        print("No customer email or name, skipping training_clients update")
        return

    email = (customer_email or "").strip().lower()
    name = (customer_name or "").strip()

    clients = load_training_clients()

    # Find existing client
    existing = None
    for c in clients:
        c_email = (c.get("email") or "").strip().lower()
        c_name = (c.get("name") or "").strip()
        if email and c_email and email == c_email:
            existing = c
            break
        if name and c_name and name.lower() == c_name.lower():
            existing = c
            break

    now_iso = datetime.utcnow().isoformat()

    if existing:
        # Update in place
        if email:
            existing["email"] = email
        if name:
            existing["name"] = name

        existing["coaching_tier"] = tier
        existing["billing_status"] = billing_status

        # Map billing_status to client status
        if billing_status in ("canceled", "unpaid", "past_due"):
            # You can tweak this mapping however you want
            existing["status"] = "paused"
        else:
            existing.setdefault("status", "active")
            if existing["status"] != "paused":
                existing["status"] = "active"

        existing["last_billing_update"] = now_iso
        print("Updated existing training client from Stripe:", existing.get("name") or existing.get("email"))
    else:
        # Create new client entry
        slug = slugify(name or email)
        year = datetime.utcnow().year
        client_id = f"train_{slug}_{year}"

        new_client = {
            "id": client_id,
            "name": name or email.split("@")[0],
            "email": email or None,
            "phone": None,
            "status": "active" if billing_status not in ("canceled", "unpaid") else "paused",
            "coaching_tier": tier,
            "billing_status": billing_status,
            "program_current": "",
            "program_start_date": None,
            "program_last_updated": None,
            "program_history": [],
            "last_checkin": None,
            "notes": "Created from Stripe subscription webhook",
            "checkin_history": [],
            "created_from": "stripe",
            "created_at": now_iso,
        }
        clients.append(new_client)
        print("Created new training client from Stripe:", new_client["name"])

    save_training_clients(clients)


# ---------- Routes ----------

@app.get("/")
async def root():
    return {"status": "ok", "service": "zachfit-backend"}


@app.post("/stripe-webhook")
async def stripe_webhook(request: Request):
    """
    Stripe webhook endpoint.
    Listens for checkout.session.completed and subscription updates,
    then syncs coaching_tier + billing_status into training_clients.
    """
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
        raise HTTPException(status_code=400, detail="Invalid payload")
    except stripe.error.SignatureVerificationError:
        raise HTTPException(status_code=400, detail="Invalid signature")

    event_type = event["type"]
    data = event["data"]["object"]

    print("Received Stripe event:", event_type)

    # --- Handle checkout.session.completed (new subscription) ---
    if event_type == "checkout.session.completed":
        customer_email = data.get("customer_details", {}).get("email")
        customer_name = data.get("customer_details", {}).get("name")

        # Get price_id from the session's line items
        price_id = None
        try:
            session = stripe.checkout.Session.retrieve(
                data["id"],
                expand=["line_items"],
            )
            line_items = session.get("line_items", {}).get("data", [])
            if line_items:
                price_id = line_items[0]["price"]["id"]
        except Exception as e:
            print("Error fetching checkout.session line items:", e)

        tier = map_price_to_tier(price_id)
        billing_status = "active"  # brand new checkout that completed

        update_training_client_from_stripe(
            customer_email=customer_email,
            customer_name=customer_name,
            tier=tier,
            billing_status=billing_status,
        )

    # --- Handle subscription updates / cancellations ---
    elif event_type in (
        "customer.subscription.created",
        "customer.subscription.updated",
        "customer.subscription.deleted",
    ):
        # Subscription object
        subscription = data
        status = subscription.get("status")  # active, past_due, canceled, unpaid, etc.

        # Find price_id from subscription items
        price_id = None
        items = subscription.get("items", {}).get("data", [])
        if items:
            price_id = items[0].get("price", {}).get("id")

        tier = map_price_to_tier(price_id)

        # Fetch customer details for email/name
        customer_email = None
        customer_name = None
        try:
            customer_id = subscription.get("customer")
            if customer_id:
                customer = stripe.Customer.retrieve(customer_id)
                customer_email = customer.get("email")
                customer_name = customer.get("name")
        except Exception as e:
            print("Error fetching Stripe customer:", e)

        update_training_client_from_stripe(
            customer_email=customer_email,
            customer_name=customer_name,
            tier=tier,
            billing_status=status or "unknown",
        )

    # You can add more event types here if needed

    return {"received": True}
