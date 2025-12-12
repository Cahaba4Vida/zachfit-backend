# main.py — ZachFit backend (Stripe webhooks -> Jarvas memory)
# Python 3.11+ recommended

import os
import json
import logging
from datetime import datetime
from typing import Any, Optional, Dict, List, Tuple

import re

import stripe
import requests
from fastapi import FastAPI, Request, HTTPException, Response
from fastapi.responses import JSONResponse


# ------------------------------------------------------------
# Logging
# ------------------------------------------------------------
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("zachfit-backend")


# ------------------------------------------------------------
# App
# ------------------------------------------------------------
app = FastAPI()


# ------------------------------------------------------------
# ENV
# ------------------------------------------------------------
# Stripe
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")
STRIPE_LITE_PRICE_ID = os.getenv("STRIPE_LITE_PRICE_ID")
STRIPE_STANDARD_PRICE_ID = os.getenv("STRIPE_STANDARD_PRICE_ID")

# Jarvas (Redis-backed memory API)
JARVAS_BASE_URL = os.getenv("JARVAS_BASE_URL", "https://jarvas-memory-api-1.onrender.com").rstrip("/")
JARVAS_USER_ID = os.getenv("JARVAS_USER_ID", "zach")
# This MUST be the ADMIN key for the Jarvas memory service
JARVAS_API_KEY = os.getenv("JARVAS_API_KEY") or os.getenv("MEMORY_API_KEY_ADMIN")

# If Jarvas is unavailable during webhook processing, return 503 so Stripe retries
FAIL_CLOSED = os.getenv("FAIL_CLOSED", "true").lower() in ("1", "true", "yes", "y")

# Wire Stripe SDK
stripe.api_key = STRIPE_SECRET_KEY


# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------
def iso_now() -> str:
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"


def slugify_name(name: Optional[str]) -> str:
    if not name:
        return "client"
    return (
        name.strip()
        .lower()
        .replace(" ", "_")
        .replace("@", "_")
        .replace(".", "_")
    )


def normalize_phone(phone: Optional[str]) -> Optional[str]:
    """
    Normalize a phone number to 10 digits:
    - Strip non-digits
    - Drop leading '1' if 11 digits
    - Return None if not exactly 10 digits
    """
    if not phone:
        return None
    digits = re.sub(r"\D", "", phone)
    if len(digits) == 11 and digits.startswith("1"):
        digits = digits[1:]
    if len(digits) != 10:
        return None
    return digits


# ------------------------------------------------------------
# Jarvas Client (JSON-safe, fail-closed)
# ------------------------------------------------------------
class JarvasUnavailable(RuntimeError):
    """Raised when Jarvas memory store can't be reached or returns non-2xx."""


def jarvas_headers() -> dict:
    h: dict = {"content-type": "application/json"}
    if JARVAS_API_KEY:
        h["x-api-key"] = JARVAS_API_KEY
    return h


def _maybe_parse_json_string(v: Any) -> Any:
    """
    Jarvas may return:
      - list/dict (JSON-safe Jarvas)
      - string "..." (older values)
    If it's a JSON-looking string, try to parse it.
    """
    if not isinstance(v, str):
        return v

    s = v.strip()
    if not s:
        return v

    if s[0] in "[{\"" or s in ("null", "true", "false") or s.replace(".", "", 1).isdigit():
        try:
            return json.loads(s)
        except Exception:
            return v
    return v


def jarvas_get_all(user_id: str = JARVAS_USER_ID) -> Dict[str, Any]:
    """
    Returns dict of memory {key: value}.
    Raises JarvasUnavailable on any error (so we don't accidentally wipe data).
    """
    if not JARVAS_API_KEY:
        raise JarvasUnavailable("JARVAS_API_KEY missing")

    try:
        r = requests.get(
            f"{JARVAS_BASE_URL}/get_memory",
            params={"user_id": user_id},
            headers=jarvas_headers(),
            timeout=10,
        )
        r.raise_for_status()
        data = r.json()

        out: Dict[str, Any] = {}
        for mem in data.get("memories", []):
            k = mem.get("key")
            v = mem.get("value")
            if k:
                out[k] = _maybe_parse_json_string(v)
        return out

    except Exception as e:
        raise JarvasUnavailable(f"Jarvas get_memory failed: {e!r}") from e


def jarvas_get_key(key: str, default: Any = None, user_id: str = JARVAS_USER_ID) -> Any:
    store = jarvas_get_all(user_id=user_id)
    return store.get(key, default)


def jarvas_set_key(key: str, value: Any, user_id: str = JARVAS_USER_ID) -> None:
    if not JARVAS_API_KEY:
        raise JarvasUnavailable("JARVAS_API_KEY missing")

    payload = {"user_id": user_id, "key": key, "value": value}
    try:
        r = requests.post(
            f"{JARVAS_BASE_URL}/save_memory",
            json=payload,
            headers=jarvas_headers(),
            timeout=10,
        )
        r.raise_for_status()
    except Exception as e:
        raise JarvasUnavailable(f"Jarvas save_memory failed: {e!r}") from e


def coerce_list_of_dicts(v: Any) -> List[dict]:
    if v is None:
        return []
    if isinstance(v, list):
        return [x for x in v if isinstance(x, dict)]
    if isinstance(v, str):
        parsed = _maybe_parse_json_string(v)
        if isinstance(parsed, list):
            return [x for x in parsed if isinstance(x, dict)]
    return []


def patch_client_meta_for_phone(
    phone10: str,
    *,
    coaching_tier: Optional[str] = None,
    billing_status: Optional[str] = None,
    billing: Optional[Dict[str, Any]] = None,
) -> None:
    """
    Upsert client_meta under user_id=f"client:{phone10}" in Jarvas memory.

    - Reads current client_meta (if any)
    - Applies provided fields (only those that are not None)
    - Ensures created_at / updated_at
    """
    user_id = f"client:{phone10}"
    store = jarvas_get_all(user_id=user_id)
    current_meta = store.get("client_meta") or {}

    if not isinstance(current_meta, dict):
        current_meta = {}

    merged = dict(current_meta)

    if coaching_tier is not None:
        merged["coaching_tier"] = coaching_tier
    if billing_status is not None:
        merged["billing_status"] = billing_status
    if billing is not None:
        merged["billing"] = billing

    now = iso_now()
    merged.setdefault("created_at", now)
    merged["updated_at"] = now

    jarvas_set_key("client_meta", merged, user_id=user_id)


# ------------------------------------------------------------
# Stripe helpers
# ------------------------------------------------------------
def infer_tier_from_price(price_id: Optional[str]) -> str:
    if not price_id:
        return "unknown"
    if STRIPE_LITE_PRICE_ID and price_id == STRIPE_LITE_PRICE_ID:
        return "ai_only"
    if STRIPE_STANDARD_PRICE_ID and price_id == STRIPE_STANDARD_PRICE_ID:
        return "standard"
    return "unknown"


def get_customer_email_name(
    customer_id: Optional[str],
    fallback_email: Optional[str],
    fallback_name: Optional[str],
) -> Tuple[Optional[str], Optional[str]]:
    """
    Stripe events are inconsistent: best source is Customer.retrieve(customer_id)
    """
    email = fallback_email
    name = fallback_name

    if customer_id:
        try:
            cust = stripe.Customer.retrieve(customer_id)
            email = cust.get("email") or email
            name = cust.get("name") or name
        except Exception as e:
            log.warning("Stripe Customer.retrieve failed: %r", e)

    if email:
        email = email.strip().lower()

    return email, name


def get_price_id_from_subscription(subscription_id: Optional[str]) -> Optional[str]:
    if not subscription_id:
        return None
    try:
        sub = stripe.Subscription.retrieve(subscription_id, expand=["items.data.price"])
        items = (sub.get("items") or {}).get("data") or []
        if items:
            price = items[0].get("price") or {}
            return price.get("id")
    except Exception as e:
        log.warning("Stripe Subscription.retrieve failed: %r", e)
    return None


def get_price_id_from_checkout_session(session_obj: dict) -> Optional[str]:
    # Preferred: subscription -> price
    sub_id = session_obj.get("subscription")
    if isinstance(sub_id, str) and sub_id:
        pid = get_price_id_from_subscription(sub_id)
        if pid:
            return pid

    # fallback: retrieve session expanded line_items
    try:
        sess_id = session_obj.get("id")
        if not sess_id:
            return None
        sess = stripe.checkout.Session.retrieve(sess_id, expand=["line_items.data.price"])
        line_items = (sess.get("line_items") or {}).get("data") or []
        if line_items:
            price = line_items[0].get("price") or {}
            return price.get("id")
    except Exception as e:
        log.warning("Stripe Session.retrieve(line_items) failed: %r", e)

    return None


# ------------------------------------------------------------
# Idempotency marker (stored in Jarvas)
# ------------------------------------------------------------
def already_processed_event(event_id: str) -> bool:
    marker_key = f"stripe_event:{event_id}"
    try:
        v = jarvas_get_key(marker_key, default=None)
        return v is not None
    except JarvasUnavailable:
        return False


def mark_event_processed(event_id: str) -> None:
    marker_key = f"stripe_event:{event_id}"
    jarvas_set_key(marker_key, {"processed_at": iso_now()})


# ------------------------------------------------------------
# training_clients upsert (no-wipe safe, email-based roster for Jarvas admin)
# ------------------------------------------------------------
def upsert_training_client(
    *,
    email: Optional[str],
    name: Optional[str],
    price_id: Optional[str],
    billing_status: str,
    source: str,
) -> None:
    if not email:
        log.info("No email; skipping training_clients upsert.")
        return

    coaching_tier = infer_tier_from_price(price_id)
    store = jarvas_get_all()
    clients = coerce_list_of_dicts(store.get("training_clients"))

    now = iso_now()
    year = datetime.utcnow().year

    existing = None
    for c in clients:
        if (c.get("email") or "").strip().lower() == email:
            existing = c
            break

    if existing:
        existing["email"] = email
        existing["name"] = existing.get("name") or name
        if coaching_tier != "unknown":
            existing["coaching_tier"] = coaching_tier
        existing["billing_status"] = billing_status or existing.get("billing_status", "unknown")
        existing["status"] = existing.get("status") or "active"
        existing["billing_last_updated"] = now
        existing["updated_at"] = now
        existing["source"] = existing.get("source") or source
    else:
        slug = slugify_name(name or email)
        new_client = {
            "id": f"train_{slug}_{year}",
            "name": name,
            "phone": None,
            "email": email,
            "status": "active",
            "coaching_tier": coaching_tier,
            "billing_status": billing_status,
            "goals": "",
            "notes": "",
            "training_profile": {
                "experience_level": "unknown",
                "days_per_week": None,
                "preferred_split": None,
                "constraints": [],
                "equipment": "unknown",
            },
            "program_current": None,
            "program_history": [],
            "last_checkin": None,
            "checkin_history": [],
            "billing": None,
            "billing_last_updated": now,
            "source": source,
            "created_at": now,
            "updated_at": now,
        }
        clients.append(new_client)

    jarvas_set_key("training_clients", clients)


# ------------------------------------------------------------
# Routes
# ------------------------------------------------------------
@app.get("/")
async def root():
    return {"status": "ok", "service": "zachfit-backend", "time": iso_now()}


@app.get("/healthz")
async def healthz():
    """
    SHALLOW health check for Render:
    - MUST return 200 even if Jarvas is down/rate-limited
    - SHOULD NOT call external services
    """
    return {
        "ok": True,
        "time": iso_now(),
        "stripe_configured": bool(STRIPE_SECRET_KEY and STRIPE_WEBHOOK_SECRET),
    }


@app.get("/readyz")
async def readyz(response: Response):
    """
    DEEP readiness check (does not need to be used by Render):
    - Checks Jarvas /healthz (no API key, no expensive get_memory)
    - Reports Stripe config presence
    """
    ok = True
    jarvas_status = "ok"

    # Stripe config presence
    stripe_ok = bool(STRIPE_SECRET_KEY and STRIPE_WEBHOOK_SECRET)
    if not stripe_ok:
        ok = False

    # Jarvas cheap check (prefer /healthz over /get_memory to avoid 429)
    try:
        r = requests.get(f"{JARVAS_BASE_URL}/healthz", timeout=5)
        if not r.ok:
            ok = False
            jarvas_status = f"bad_status:{r.status_code}"
    except Exception as e:
        ok = False
        jarvas_status = f"unavailable:{e!r}"

    response.status_code = 200 if ok else 503
    return {
        "ok": ok,
        "time": iso_now(),
        "stripe_configured": stripe_ok,
        "jarvas": jarvas_status,
        "jarvas_base_url": JARVAS_BASE_URL,
    }


@app.post("/stripe-webhook")
async def stripe_webhook(request: Request):
    # Basic env validation
    if not STRIPE_SECRET_KEY:
        raise HTTPException(status_code=500, detail="STRIPE_SECRET_KEY not configured")
    if not STRIPE_WEBHOOK_SECRET:
        raise HTTPException(status_code=500, detail="STRIPE_WEBHOOK_SECRET not configured")

    payload = await request.body()
    sig_header = request.headers.get("Stripe-Signature")

    try:
        event = stripe.Webhook.construct_event(
            payload=payload,
            sig_header=sig_header,
            secret=STRIPE_WEBHOOK_SECRET,
        )
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid payload")
    except stripe.error.SignatureVerificationError:
        raise HTTPException(status_code=400, detail="Invalid signature")

    event_id = event.get("id") or ""
    event_type = event.get("type")
    obj: dict = event["data"]["object"]

    log.info("Stripe event received: type=%s id=%s", event_type, event_id)

    # Idempotency (best effort)
    try:
        if event_id and already_processed_event(event_id):
            log.info("Stripe event already processed, skipping: %s", event_id)
            return {"received": True, "skipped": True}
    except Exception as e:
        log.warning("Idempotency check failed: %r", e)

    try:
        # ---------------------------------------------------------------------
        # checkout.session.completed
        # ---------------------------------------------------------------------
        if event_type == "checkout.session.completed":
            customer_id = obj.get("customer")
            details = obj.get("customer_details") or {}
            fallback_email = details.get("email") or obj.get("customer_email")
            fallback_name = details.get("name")

            email, name = get_customer_email_name(customer_id, fallback_email, fallback_name)
            price_id = get_price_id_from_checkout_session(obj)

            # Maintain email-based training_clients for Jarvas admin
            upsert_training_client(
                email=email,
                name=name,
                price_id=price_id,
                billing_status="active",
                source="stripe_checkout",
            )

            # Phone-based client_meta for Coach / portal gating
            raw_phone = (obj.get("metadata") or {}).get("phone") or details.get("phone")
            phone10 = normalize_phone(raw_phone)
            if phone10:
                coaching_tier = infer_tier_from_price(price_id)
                plan_type = "standard" if coaching_tier == "standard" else (
                    "lite" if coaching_tier == "ai_only" else "unknown"
                )

                billing: Dict[str, Any] = {
                    "stripe_customer_id": customer_id,
                    "stripe_subscription_id": obj.get("subscription"),
                    "plan_id": price_id,
                    "plan_type": plan_type,
                    "current_period_end": None,  # can be refined from Subscription if needed
                }

                patch_client_meta_for_phone(
                    phone10,
                    coaching_tier=coaching_tier,
                    billing_status="active",
                    billing=billing,
                )

        # ---------------------------------------------------------------------
        # customer.subscription.* (created/updated/deleted)
        # Keep training_clients in sync and refine client_meta billing_status
        # ---------------------------------------------------------------------
        elif event_type in (
            "customer.subscription.created",
            "customer.subscription.updated",
            "customer.subscription.deleted",
        ):
            customer_id = obj.get("customer")
            email, name = get_customer_email_name(customer_id, None, None)

            items = (obj.get("items") or {}).get("data") or []
            price_id = None
            if items:
                price_id = ((items[0].get("price") or {}).get("id"))

            billing_status = obj.get("status") or ("canceled" if event_type.endswith("deleted") else "unknown")

            upsert_training_client(
                email=email,
                name=name,
                price_id=price_id,
                billing_status=billing_status,
                source="stripe_subscription",
            )

            # Update client_meta if we can resolve phone from subscription metadata
            raw_phone = (obj.get("metadata") or {}).get("phone")
            phone10 = normalize_phone(raw_phone)
            if phone10:
                coaching_tier = infer_tier_from_price(price_id)
                plan_type = "standard" if coaching_tier == "standard" else (
                    "lite" if coaching_tier == "ai_only" else "unknown"
                )

                current_period_end_iso: Optional[str] = None
                cpe = obj.get("current_period_end")
                if cpe:
                    current_period_end_iso = datetime.utcfromtimestamp(cpe).isoformat() + "Z"

                billing: Dict[str, Any] = {
                    "stripe_customer_id": customer_id,
                    "stripe_subscription_id": obj.get("id"),
                    "plan_id": price_id,
                    "plan_type": plan_type,
                    "current_period_end": current_period_end_iso,
                }

                patch_client_meta_for_phone(
                    phone10,
                    coaching_tier=coaching_tier,
                    billing_status=billing_status,
                    billing=billing,
                )

        # ---------------------------------------------------------------------
        # invoice.payment_failed
        # Keep roster indicator for email-based training_clients
        # Subscription.updated will handle client_meta billing_status
        # ---------------------------------------------------------------------
        elif event_type == "invoice.payment_failed":
            customer_id = obj.get("customer")
            subscription_id = obj.get("subscription")

            email, name = get_customer_email_name(customer_id, obj.get("customer_email"), obj.get("customer_name"))
            price_id = get_price_id_from_subscription(subscription_id)

            upsert_training_client(
                email=email,
                name=name,
                price_id=price_id,
                billing_status="past_due",
                source="stripe_invoice",
            )

        # ignore other events

        # Mark processed ONLY after successful handling
        if event_id:
            mark_event_processed(event_id)

        return {"received": True}

    except JarvasUnavailable as e:
        log.error("Jarvas unavailable while processing Stripe event: %r", e)
        if FAIL_CLOSED:
            # make Stripe retry later
            raise HTTPException(status_code=503, detail="Memory store unavailable; retry later")
        return {"received": True, "warning": "memory store unavailable"}

    except Exception as e:
        log.exception("Webhook handler error: %r", e)
        raise HTTPException(status_code=500, detail="Webhook handler failed")
