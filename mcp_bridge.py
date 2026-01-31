"""
SSE-to-stdio MCP Bridge for mcp-atlassian.

Accepts SSE connections from LibreChat, identifies the user via
X-User-Email header, fetches their Atlassian token from Redis,
spawns a per-user mcp-atlassian subprocess, and bridges
SSE ↔ stdio (MCP JSON-RPC messages).
"""

import asyncio
import json
import logging
import os
import shutil
import uuid

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route
from sse_starlette.sse import EventSourceResponse

logger = logging.getLogger("mcp-bridge")

# Per-session state: session_id -> { process, email, queue }
_sessions: dict[str, dict] = {}


def create_mcp_bridge(token_store):
    """
    Create a Starlette app that bridges SSE MCP connections to
    mcp-atlassian stdio subprocesses.

    Args:
        token_store: TokenStore instance for fetching user tokens.

    Returns:
        Starlette application with /sse and /messages endpoints.
    """

    async def sse_endpoint(request: Request):
        """
        GET /sse — SSE event stream for MCP.

        LibreChat connects here. We:
        1. Read user email from X-User-Email header
        2. Fetch their Atlassian token from Redis
        3. Spawn mcp-atlassian subprocess
        4. Stream subprocess stdout as SSE events
        5. Send the messages endpoint URL as first event
        """
        email = request.headers.get("x-user-email", "").strip().lower()
        if not email:
            return JSONResponse(
                {"error": "X-User-Email header is required"},
                status_code=400,
            )

        # Fetch user token
        entry = token_store.get(email)
        if not entry or not entry.get("access_token"):
            return JSONResponse(
                {"error": f"No Atlassian token for {email}. User must complete OAuth consent first."},
                status_code=401,
            )

        session_id = uuid.uuid4().hex
        logger.info("SSE connection from %s (session: %s)", email, session_id)

        # Build env for mcp-atlassian
        child_env = os.environ.copy()
        # Disable SSL verification for corporate proxies (Zscaler, Cisco, etc.)
        child_env["PYTHONHTTPSVERIFY"] = "0"
        child_env["CURL_CA_BUNDLE"] = ""
        child_env["REQUESTS_CA_BUNDLE"] = ""
        child_env["ATLASSIAN_OAUTH_ACCESS_TOKEN"] = entry["access_token"]
        child_env["ATLASSIAN_OAUTH_CLOUD_ID"] = entry.get("cloud_id", "")
        child_env["ATLASSIAN_OAUTH_ENABLE"] = "true"
        site_url = entry.get("site_url", "")
        if site_url:
            child_env["JIRA_URL"] = site_url
            child_env["CONFLUENCE_URL"] = f"{site_url}/wiki"

        # Find mcp-atlassian executable
        mcp_bin = shutil.which("mcp-atlassian")
        if not mcp_bin:
            logger.error("mcp-atlassian not found in PATH")
            return JSONResponse(
                {"error": "mcp-atlassian not installed in gateway container"},
                status_code=500,
            )

        # Spawn mcp-atlassian subprocess
        try:
            process = await asyncio.create_subprocess_exec(
                mcp_bin,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=child_env,
            )
        except Exception as e:
            logger.error("Failed to spawn mcp-atlassian: %s", e)
            return JSONResponse(
                {"error": f"Failed to spawn mcp-atlassian: {e}"},
                status_code=500,
            )

        # Queue for messages from subprocess stdout → SSE
        queue: asyncio.Queue = asyncio.Queue()

        _sessions[session_id] = {
            "process": process,
            "email": email,
            "queue": queue,
        }

        # Background task: read subprocess stdout and enqueue messages
        async def read_stdout():
            try:
                while True:
                    line = await process.stdout.readline()
                    if not line:
                        break
                    text = line.decode("utf-8").strip()
                    if text:
                        logger.debug("stdout [%s]: %s", session_id[:8], text[:200])
                        await queue.put(text)
            except Exception as e:
                logger.error("stdout reader error [%s]: %s", session_id[:8], e)
            finally:
                await queue.put(None)  # Signal end

        # Background task: log subprocess stderr
        async def read_stderr():
            try:
                while True:
                    line = await process.stderr.readline()
                    if not line:
                        break
                    text = line.decode("utf-8").strip()
                    if text:
                        logger.debug("stderr [%s]: %s", session_id[:8], text[:200])
            except Exception:
                pass

        stdout_task = asyncio.create_task(read_stdout())
        stderr_task = asyncio.create_task(read_stderr())

        async def event_generator():
            try:
                # First event: tell the client the messages endpoint URL
                messages_url = f"{_get_base_url(request)}/messages?session_id={session_id}"
                yield {
                    "event": "endpoint",
                    "data": messages_url,
                }

                # Stream subprocess stdout as SSE message events
                while True:
                    msg = await queue.get()
                    if msg is None:
                        break
                    yield {
                        "event": "message",
                        "data": msg,
                    }
            except asyncio.CancelledError:
                logger.info("SSE connection cancelled [%s]", session_id[:8])
            finally:
                await _cleanup_session(session_id)
                stdout_task.cancel()
                stderr_task.cancel()

        return EventSourceResponse(event_generator())

    async def messages_endpoint(request: Request):
        """
        POST /messages?session_id=xxx — receive JSON-RPC messages from LibreChat.

        Forwards the message to the mcp-atlassian subprocess stdin.
        """
        session_id = request.query_params.get("session_id", "")
        session = _sessions.get(session_id)

        if not session:
            return JSONResponse(
                {"error": "Invalid or expired session"},
                status_code=404,
            )

        process = session["process"]
        if process.returncode is not None:
            return JSONResponse(
                {"error": "mcp-atlassian process has terminated"},
                status_code=500,
            )

        try:
            body = await request.body()
            text = body.decode("utf-8").strip()
            logger.debug("POST [%s]: %s", session_id[:8], text[:200])

            # Write to subprocess stdin
            process.stdin.write((text + "\n").encode("utf-8"))
            await process.stdin.drain()

            return Response(status_code=202)
        except Exception as e:
            logger.error("Failed to forward message [%s]: %s", session_id[:8], e)
            return JSONResponse(
                {"error": f"Failed to forward message: {e}"},
                status_code=500,
            )

    async def _cleanup_session(session_id: str):
        """Kill subprocess and remove session."""
        session = _sessions.pop(session_id, None)
        if not session:
            return

        process = session["process"]
        if process.returncode is None:
            try:
                process.terminate()
                try:
                    await asyncio.wait_for(process.wait(), timeout=5)
                except asyncio.TimeoutError:
                    process.kill()
                    await process.wait()
            except Exception as e:
                logger.error("Cleanup error [%s]: %s", session_id[:8], e)

        logger.info("Session cleaned up [%s] for %s", session_id[:8], session["email"])

    def _get_base_url(request: Request) -> str:
        """Get the base URL for constructing the messages endpoint URL."""
        scheme = request.headers.get("x-forwarded-proto", request.url.scheme)
        host = request.headers.get("x-forwarded-host", request.headers.get("host", "localhost"))
        return f"{scheme}://{host}"

    routes = [
        Route("/sse", sse_endpoint, methods=["GET"]),
        Route("/messages", messages_endpoint, methods=["POST"]),
    ]

    return Starlette(routes=routes)
