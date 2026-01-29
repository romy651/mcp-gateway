"""
Atlassian OAuth 2.0 (3LO) Gateway for LibreChat MCP integration.

Manages per-user Atlassian OAuth tokens. On first use, the user does a
one-time Atlassian consent. After that, tokens are refreshed silently.

Run: python gateway.py
Or:  uvicorn gateway:app --host 0.0.0.0 --port 3001

Endpoints:
  GET  /connect?email=<email>  — Start Atlassian OAuth consent for a user
  GET  /callback               — OAuth callback (Atlassian redirects here)
  POST /get-token              — Get a fresh Atlassian access token for a user
  GET  /status?email=<email>   — Check if a user is connected
  GET  /health                 — Health check
"""

import logging
import os
import secrets
import sys
import time
import urllib.parse

import httpx
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel

from token_store import TokenStore

from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("atlassian-gateway")

app = FastAPI(title="Atlassian OAuth Gateway", version="2.0.0")

# Token store: Redis-backed with encryption at rest
# Requires REDIS_URL and TOKEN_ENCRYPTION_KEY in environment
try:
    store = TokenStore(
        redis_url=os.environ.get("REDIS_URL", "redis://localhost:6379/0"),
        encryption_key=os.environ.get("TOKEN_ENCRYPTION_KEY", ""),
    )
except ValueError as e:
    logger.error("Failed to initialize token store: %s", e)
    sys.exit(1)

# In-memory state storage for OAuth CSRF protection
_oauth_states: dict[str, dict] = {}

# Atlassian OAuth 2.0 endpoints
ATLASSIAN_AUTH_URL = "https://auth.atlassian.com/authorize"
ATLASSIAN_TOKEN_URL = "https://auth.atlassian.com/oauth/token"
ATLASSIAN_RESOURCES_URL = "https://api.atlassian.com/oauth/token/accessible-resources"


def _get_config():
    """Read Atlassian OAuth config from environment."""
    client_id = os.environ.get("ATLASSIAN_OAUTH_CLIENT_ID", "")
    client_secret = os.environ.get("ATLASSIAN_OAUTH_CLIENT_SECRET", "")
    callback_url = os.environ.get(
        "ATLASSIAN_OAUTH_CALLBACK_URL", "http://localhost:3001/callback"
    )
    scopes = os.environ.get(
        "ATLASSIAN_OAUTH_SCOPES",
        # Jira classic scopes
        "read:jira-work write:jira-work "
        # Confluence classic scopes
        "read:confluence-content.all write:confluence-content "
        "read:confluence-space.summary write:confluence-space "
        "read:confluence-props write:confluence-props "
        "read:confluence-content.permission "
        "read:confluence-content.summary "
        "read:confluence-user read:confluence-groups "
        "search:confluence "
        "write:confluence-file "
        # Confluence granular scopes (required by v2 API)
        "read:space:confluence write:space:confluence "
        "read:page:confluence write:page:confluence "
        "read:content:confluence "
        # Token management
        "offline_access",
    )

    if not client_id or not client_secret:
        raise HTTPException(
            status_code=500,
            detail="Server misconfigured: ATLASSIAN_OAUTH_CLIENT_ID and "
            "ATLASSIAN_OAUTH_CLIENT_SECRET must be set.",
        )

    return {
        "client_id": client_id,
        "client_secret": client_secret,
        "callback_url": callback_url,
        "scopes": scopes,
    }


# ─── Endpoints ───────────────────────────────────────────────────────────────


@app.get("/health")
def health():
    """Health check."""
    return {"status": "ok", "connected_users": len(store.list_users())}


@app.get("/status")
def status(email: str = Query(..., description="User email address")):
    """Check if a user has connected their Atlassian account."""
    connected = store.has_user(email)
    return {"email": email, "connected": connected}


@app.get("/connect")
def connect(email: str = Query(..., description="User email to link")):
    """
    Start Atlassian OAuth 2.0 consent flow for a user.
    Redirects to Atlassian authorization page.
    """
    config = _get_config()

    # Generate CSRF state token
    state = secrets.token_urlsafe(32)
    _oauth_states[state] = {
        "email": email.lower(),
        "created_at": time.time(),
    }

    # Clean up old states (older than 10 minutes)
    cutoff = time.time() - 600
    expired = [k for k, v in _oauth_states.items() if v["created_at"] < cutoff]
    for k in expired:
        del _oauth_states[k]

    params = {
        "audience": "api.atlassian.com",
        "client_id": config["client_id"],
        "scope": config["scopes"],
        "redirect_uri": config["callback_url"],
        "state": state,
        "response_type": "code",
        "prompt": "consent",
    }

    auth_url = f"{ATLASSIAN_AUTH_URL}?{urllib.parse.urlencode(params)}"

    logger.info("Redirecting user %s to Atlassian consent: %s", email, auth_url)
    return RedirectResponse(url=auth_url)


@app.get("/callback")
async def callback(
    code: str = Query(...),
    state: str = Query(...),
):
    """
    OAuth callback. Atlassian redirects here after user consents.
    Exchanges the authorization code for tokens and stores them.
    """
    # Validate state
    state_data = _oauth_states.pop(state, None)
    if not state_data:
        raise HTTPException(status_code=400, detail="Invalid or expired OAuth state")

    email = state_data["email"]
    config = _get_config()

    # Exchange authorization code for tokens
    async with httpx.AsyncClient(verify=False) as client:
        token_response = await client.post(
            ATLASSIAN_TOKEN_URL,
            json={
                "grant_type": "authorization_code",
                "client_id": config["client_id"],
                "client_secret": config["client_secret"],
                "code": code,
                "redirect_uri": config["callback_url"],
            },
        )

    if token_response.status_code != 200:
        logger.error(
            "Token exchange failed: %s %s",
            token_response.status_code,
            token_response.text,
        )
        raise HTTPException(
            status_code=400,
            detail=f"Token exchange failed: {token_response.text}",
        )

    tokens = token_response.json()
    logger.info("Token exchange succeeded for %s", email)

    # Get accessible resources (cloud ID and site URL)
    cloud_info = await _get_cloud_info(tokens["access_token"])
    cloud_id = cloud_info["cloud_id"]
    site_url = cloud_info["site_url"]

    # Store tokens
    store.put(email, {
        "access_token": tokens["access_token"],
        "refresh_token": tokens.get("refresh_token", ""),
        "expires_at": time.time() + tokens.get("expires_in", 3600),
        "scope": tokens.get("scope", ""),
        "cloud_id": cloud_id,
        "site_url": site_url,
    })

    return HTMLResponse(
        content=f"""
        <html>
        <body style="font-family: sans-serif; text-align: center; padding: 60px;">
            <h1>Atlassian Connected</h1>
            <p>Your Atlassian account has been linked for <strong>{email}</strong>.</p>
            <p>This tab will close automatically. Return to LibreChat.</p>
            <script>setTimeout(() => window.close(), 2000);</script>
        </body>
        </html>
        """,
        status_code=200,
    )


class TokenRequest(BaseModel):
    email: str


@app.post("/get-token")
async def get_token(req: TokenRequest):
    """
    Get a fresh Atlassian access token for a user.
    Automatically refreshes expired tokens using the stored refresh token.

    Returns:
        - access_token, cloud_id if the user is connected
        - 401 with a connect_url if the user needs to authorize
    """
    email = req.email.lower()
    entry = store.get(email)

    if not entry or not entry.get("refresh_token"):
        gateway_url = os.environ.get("GATEWAY_URL", "http://localhost:3001")
        connect_url = f"{gateway_url}/connect?email={email}"
        raise HTTPException(
            status_code=401,
            detail={
                "error": "not_connected",
                "message": f"User {email} has not connected their Atlassian account.",
                "connect_url": connect_url,
                "instructions": (
                    "Please visit the connect_url in your browser to link "
                    "your Atlassian account. This is a one-time setup."
                ),
            },
        )

    # Check if token is expired (with 2-minute buffer)
    if time.time() >= entry.get("expires_at", 0) - 120:
        logger.info("Token expired for %s, refreshing", email)
        try:
            entry = await _refresh_token(email, entry)
        except Exception as e:
            logger.error("Token refresh failed for %s: %s", email, e)
            # Remove invalid tokens so user can re-authorize
            store.remove(email)
            gateway_url = os.environ.get("GATEWAY_URL", "http://localhost:3001")
            connect_url = f"{gateway_url}/connect?email={email}"
            raise HTTPException(
                status_code=401,
                detail={
                    "error": "refresh_failed",
                    "message": f"Token refresh failed: {e}. Please re-authorize.",
                    "connect_url": connect_url,
                },
            )

    return {
        "access_token": entry["access_token"],
        "cloud_id": entry.get("cloud_id", ""),
        "site_url": entry.get("site_url", ""),
        "expires_at": entry.get("expires_at", 0),
    }


# ─── Helpers ─────────────────────────────────────────────────────────────────


async def _get_cloud_info(access_token: str) -> dict:
    """Fetch the user's Atlassian Cloud ID and site URL from accessible resources."""
    async with httpx.AsyncClient(verify=False) as client:
        resp = await client.get(
            ATLASSIAN_RESOURCES_URL,
            headers={"Authorization": f"Bearer {access_token}"},
        )

    if resp.status_code != 200:
        logger.warning("Failed to get accessible resources: %s", resp.text)
        return {"cloud_id": "", "site_url": ""}

    resources = resp.json()
    if not resources:
        logger.warning("No accessible Atlassian resources found")
        return {"cloud_id": "", "site_url": ""}

    # Use the first cloud resource
    resource = resources[0]
    cloud_id = resource.get("id", "")
    site_name = resource.get("name", "unknown")
    site_url = resource.get("url", "")
    logger.info("Found Atlassian site: %s (cloud_id: %s, url: %s)", site_name, cloud_id, site_url)
    return {"cloud_id": cloud_id, "site_url": site_url}


async def _refresh_token(email: str, entry: dict) -> dict:
    """Refresh an expired Atlassian access token."""
    config = _get_config()

    async with httpx.AsyncClient(verify=False) as client:
        resp = await client.post(
            ATLASSIAN_TOKEN_URL,
            json={
                "grant_type": "refresh_token",
                "client_id": config["client_id"],
                "client_secret": config["client_secret"],
                "refresh_token": entry["refresh_token"],
            },
        )

    if resp.status_code != 200:
        raise RuntimeError(f"Refresh failed ({resp.status_code}): {resp.text}")

    tokens = resp.json()
    logger.info("Token refreshed for %s", email)

    # Fetch site_url if not already stored
    site_url = entry.get("site_url", "")
    if not site_url:
        cloud_info = await _get_cloud_info(tokens["access_token"])
        site_url = cloud_info.get("site_url", "")

    # Update stored tokens
    updated = {
        "access_token": tokens["access_token"],
        "refresh_token": tokens.get("refresh_token", entry["refresh_token"]),
        "expires_at": time.time() + tokens.get("expires_in", 3600),
        "scope": tokens.get("scope", entry.get("scope", "")),
        "cloud_id": entry.get("cloud_id", ""),
        "site_url": site_url,
    }
    store.put(email, updated)
    return updated


# ─── Main ────────────────────────────────────────────────────────────────────


if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("GATEWAY_PORT", "3001"))
    logger.info("Starting Atlassian OAuth Gateway on port %d", port)
    uvicorn.run(app, host="0.0.0.0", port=port)
