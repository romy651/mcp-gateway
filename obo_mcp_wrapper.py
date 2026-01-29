"""
Atlassian MCP Wrapper — token injector for mcp-atlassian.

This script is the MCP server command invoked by LibreChat. It:
1. Reads the user's email from LIBRECHAT_USER_EMAIL env var (set by LibreChat)
2. Calls the Atlassian OAuth Gateway to get a fresh Atlassian access token
3. Sets token env vars and execs mcp-atlassian (inheriting stdin/stdout)

All logging goes to stderr to avoid interfering with MCP JSON-RPC on stdout.
"""

import json
import logging
import os
import subprocess
import sys
import urllib.request
import urllib.error

logger = logging.getLogger("atlassian-wrapper")


def setup_logging():
    """Configure stderr logging."""
    level = os.environ.get("LOG_LEVEL", "INFO").upper()
    logging.basicConfig(
        level=getattr(logging, level, logging.INFO),
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        stream=sys.stderr,
    )


def get_atlassian_token(email: str, gateway_url: str) -> dict:
    """
    Call the Atlassian OAuth Gateway to get a fresh access token.

    Returns dict with 'access_token' and 'cloud_id' on success.
    Raises RuntimeError with instructions on failure.
    """
    url = f"{gateway_url}/get-token"
    data = json.dumps({"email": email}).encode()
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        try:
            detail = json.loads(body).get("detail", {})
        except (json.JSONDecodeError, AttributeError):
            detail = {"message": body}

        if e.code == 401:
            connect_url = detail.get("connect_url", f"{gateway_url}/connect?email={email}")
            raise RuntimeError(
                f"Atlassian account not connected for {email}.\n"
                f"Please visit this URL to link your account (one-time setup):\n"
                f"  {connect_url}\n"
                f"Then try again."
            )
        raise RuntimeError(f"Gateway error ({e.code}): {detail.get('message', body)}")
    except urllib.error.URLError as e:
        raise RuntimeError(
            f"Cannot reach the Atlassian OAuth Gateway at {gateway_url}.\n"
            f"Make sure gateway.py is running: python gateway.py\n"
            f"Error: {e.reason}"
        )


def run():
    """Main entry point."""
    setup_logging()
    logger.info("Atlassian MCP Wrapper starting")

    # Read configuration
    email = os.environ.get("LIBRECHAT_USER_EMAIL", "")
    gateway_url = os.environ.get("GATEWAY_URL", "http://localhost:3001")

    logger.info("User email: %s", email or "(empty)")

    if not email:
        logger.error(
            "LIBRECHAT_USER_EMAIL not set. "
            "Ensure the MCP server config in librechat.yaml includes:\n"
            '  env:\n    LIBRECHAT_USER_EMAIL: "{{LIBRECHAT_USER_EMAIL}}"'
        )
        sys.exit(1)

    # Get Atlassian token from gateway
    try:
        result = get_atlassian_token(email, gateway_url)
    except RuntimeError as e:
        logger.error("%s", e)
        sys.exit(1)

    atlassian_token = result["access_token"]
    cloud_id = result.get("cloud_id", "")
    site_url = result.get("site_url", "")

    if not cloud_id:
        logger.error("No Atlassian Cloud ID returned. Check gateway logs.")
        sys.exit(1)

    logger.info("Got Atlassian token for cloud %s (site: %s), starting mcp-atlassian", cloud_id, site_url)

    # Set token env vars for mcp-atlassian (inherits current environment)
    os.environ["ATLASSIAN_OAUTH_ACCESS_TOKEN"] = atlassian_token
    os.environ["ATLASSIAN_OAUTH_CLOUD_ID"] = cloud_id
    # Enable minimal OAuth mode — bypasses JIRA_URL/CONFLUENCE_URL requirement
    os.environ["ATLASSIAN_OAUTH_ENABLE"] = "true"

    # Also set URLs if available (improves mcp-atlassian functionality)
    if site_url:
        if not os.environ.get("JIRA_URL"):
            os.environ["JIRA_URL"] = site_url
            logger.info("Set JIRA_URL=%s", site_url)
        if not os.environ.get("CONFLUENCE_URL"):
            os.environ["CONFLUENCE_URL"] = f"{site_url}/wiki"
            logger.info("Set CONFLUENCE_URL=%s/wiki", site_url)

    # Find the mcp-atlassian executable in the same venv
    venv_scripts = os.path.dirname(sys.executable)
    mcp_atlassian_exe = os.path.join(venv_scripts, "mcp-atlassian.exe")
    if not os.path.exists(mcp_atlassian_exe):
        mcp_atlassian_exe = os.path.join(venv_scripts, "mcp-atlassian")

    if not os.path.exists(mcp_atlassian_exe):
        logger.error(
            "mcp-atlassian not found at %s. Install it with: pip install mcp-atlassian",
            mcp_atlassian_exe,
        )
        sys.exit(1)

    logger.info("Exec mcp-atlassian: %s", mcp_atlassian_exe)

    # Replace this process with mcp-atlassian.
    # stdin/stdout are inherited directly — no manual piping needed.
    # This avoids buffering issues and lets MCP JSON-RPC flow natively.
    if sys.platform == "win32":
        # Windows doesn't support os.execvpe reliably, use subprocess
        # with inherited stdio (no PIPE redirection)
        returncode = subprocess.call(
            [mcp_atlassian_exe],
            stdin=sys.stdin,
            stdout=sys.stdout,
            stderr=sys.stderr,
        )
        sys.exit(returncode)
    else:
        # On Unix, replace the process entirely
        os.execvpe(mcp_atlassian_exe, [mcp_atlassian_exe], os.environ)


if __name__ == "__main__":
    run()
