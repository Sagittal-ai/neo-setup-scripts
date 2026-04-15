#!/usr/bin/env python3
import argparse
import base64
import json
import logging
import os
import urllib.error
import urllib.request
from typing import Any

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger: logging.Logger = logging.getLogger(__name__)


def make_auth_header(email: str, token: str) -> str:
    credentials: str = f"{email}:{token}"
    encoded: str = base64.b64encode(credentials.encode()).decode()
    return f"Basic {encoded}"


def list_webhooks(base_url: str, email: str, token: str) -> dict[str, Any]:
    url: str = f"{base_url}/rest/webhooks/1.0/webhook"
    logger.info("Listing webhooks from %s", url)
    req: urllib.request.Request = urllib.request.Request(
        url,
        headers={
            "Content-Type": "application/json",
            "Authorization": make_auth_header(email, token),
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(req) as response:
            body: str = response.read().decode()
            logger.debug("Response received: %s", body)
            result: dict[str, Any] = json.loads(body)
            return result
    except urllib.error.HTTPError as e:
        logger.error("HTTP error listing webhooks: %s %s", e.code, e.reason)
        raise
    except urllib.error.URLError as e:
        logger.error("URL error listing webhooks: %s", e.reason)
        raise


def create_webhook(base_url: str, email: str, token: str, name: str, url: str, events: list[str]) -> dict[str, Any]:
    endpoint: str = f"{base_url}/rest/webhooks/1.0/webhook"
    logger.info("Creating webhook '%s' at %s", name, endpoint)
    data: dict[str, Any] = {"name": name, "url": url, "events": events}
    payload: bytes = json.dumps(data).encode()
    req: urllib.request.Request = urllib.request.Request(
        endpoint,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": make_auth_header(email, token),
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req) as response:
            body: str = response.read().decode()
            logger.debug("Response received: %s", body)
            result: dict[str, Any] = json.loads(body)
            return result
    except urllib.error.HTTPError as e:
        logger.error("HTTP error creating webhook: %s %s", e.code, e.reason)
        raise
    except urllib.error.URLError as e:
        logger.error("URL error creating webhook: %s", e.reason)
        raise


def get_webhook(base_url: str, email: str, token: str, webhook_id: str) -> dict[str, Any]:
    url: str = f"{base_url}/rest/webhooks/1.0/webhook/{webhook_id}"
    logger.info("Fetching webhook with ID %s from %s", webhook_id, url)
    req: urllib.request.Request = urllib.request.Request(
        url,
        headers={
            "Content-Type": "application/json",
            "Authorization": make_auth_header(email, token),
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(req) as response:
            body: str = response.read().decode()
            logger.debug("Response received: %s", body)
            result: dict[str, Any] = json.loads(body)
            return result
    except urllib.error.HTTPError as e:
        logger.error("HTTP error fetching webhook %s: %s %s", webhook_id, e.code, e.reason)
        raise
    except urllib.error.URLError as e:
        logger.error("URL error fetching webhook %s: %s", webhook_id, e.reason)
        raise


def delete_webhook(base_url: str, email: str, token: str, webhook_id: str) -> dict[str, Any]:
    url: str = f"{base_url}/rest/webhooks/1.0/webhook/{webhook_id}"
    logger.info("Deleting webhook with ID %s", webhook_id)
    req: urllib.request.Request = urllib.request.Request(
        url,
        headers={
            "Content-Type": "application/json",
            "Authorization": make_auth_header(email, token),
        },
        method="DELETE",
    )
    try:
        with urllib.request.urlopen(req) as response:
            if response.status == 204:
                logger.info("Webhook %s deleted successfully", webhook_id)
                return {"message": f"Webhook {webhook_id} deleted successfully."}
            body: str = response.read().decode()
            logger.debug("Response received: %s", body)
            result: dict[str, Any] = json.loads(body)
            return result
    except urllib.error.HTTPError as e:
        if e.code == 204:
            logger.info("Webhook %s deleted successfully", webhook_id)
            return {"message": f"Webhook {webhook_id} deleted successfully."}
        logger.error("HTTP error deleting webhook %s: %s %s", webhook_id, e.code, e.reason)
        raise
    except urllib.error.URLError as e:
        logger.error("URL error deleting webhook %s: %s", webhook_id, e.reason)
        raise


def add_common_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--base-url",
        default=os.environ.get("CONFLUENCE_BASE_URL", "https://sagittal.atlassian.net/wiki"),
        help="Confluence base URL (env: CONFLUENCE_BASE_URL)",
    )
    parser.add_argument(
        "--email",
        default=os.environ.get("CONFLUENCE_EMAIL", "neo@sagittal.ai"),
        help="Confluence account email (env: CONFLUENCE_EMAIL)",
    )
    parser.add_argument(
        "--token",
        default=os.environ.get("CONFLUENCE_API_TOKEN"),
        help="Confluence API token (env: CONFLUENCE_API_TOKEN)",
    )


def handle_list(args: argparse.Namespace) -> None:
    if not args.token:
        logger.error("API token is required. Set --token or CONFLUENCE_API_TOKEN environment variable.")
        raise SystemExit(1)
    logger.info("Listing webhooks...")
    webhooks: dict[str, Any] = list_webhooks(args.base_url, args.email, args.token)
    print(json.dumps(webhooks, indent=2))


def handle_create(args: argparse.Namespace) -> None:
    if not args.token:
        logger.error("API token is required. Set --token or CONFLUENCE_API_TOKEN environment variable.")
        raise SystemExit(1)
    events: list[str] = [e.strip() for e in args.events.split(",")]
    logger.info("Creating webhook '%s'...", args.name)
    new_webhook: dict[str, Any] = create_webhook(args.base_url, args.email, args.token, args.name, args.url, events)
    print(json.dumps(new_webhook, indent=2))


def handle_get(args: argparse.Namespace) -> None:
    if not args.token:
        logger.error("API token is required. Set --token or CONFLUENCE_API_TOKEN environment variable.")
        raise SystemExit(1)
    logger.info("Fetching webhook with ID %s...", args.webhook_id)
    webhook: dict[str, Any] = get_webhook(args.base_url, args.email, args.token, args.webhook_id)
    print(json.dumps(webhook, indent=2))


def handle_delete(args: argparse.Namespace) -> None:
    if not args.token:
        logger.error("API token is required. Set --token or CONFLUENCE_API_TOKEN environment variable.")
        raise SystemExit(1)
    logger.info("Deleting webhook with ID %s...", args.webhook_id)
    result: dict[str, Any] = delete_webhook(args.base_url, args.email, args.token, args.webhook_id)
    print(json.dumps(result, indent=2))


def build_parser() -> argparse.ArgumentParser:
    parser: argparse.ArgumentParser = argparse.ArgumentParser(
        description="Manage Confluence webhooks",
    )
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser] = parser.add_subparsers(
        dest="command", help="Sub-command to run"
    )

    list_parser: argparse.ArgumentParser = subparsers.add_parser("list", help="List all webhooks")
    add_common_args(list_parser)
    list_parser.set_defaults(func=handle_list)

    create_parser: argparse.ArgumentParser = subparsers.add_parser("create", help="Create a new webhook")
    add_common_args(create_parser)
    create_parser.add_argument("--name", required=True, help="Name of the webhook")
    create_parser.add_argument("--url", required=True, help="URL the webhook will call")
    create_parser.add_argument("--events", required=True, help="Comma-separated list of events (e.g. comment_created)")
    create_parser.set_defaults(func=handle_create)

    get_parser: argparse.ArgumentParser = subparsers.add_parser("get", help="Get a webhook by ID")
    add_common_args(get_parser)
    get_parser.add_argument("webhook_id", help="ID of the webhook to retrieve")
    get_parser.set_defaults(func=handle_get)

    delete_parser: argparse.ArgumentParser = subparsers.add_parser("delete", help="Delete a webhook by ID")
    add_common_args(delete_parser)
    delete_parser.add_argument("webhook_id", help="ID of the webhook to delete")
    delete_parser.set_defaults(func=handle_delete)

    return parser


if __name__ == "__main__":
    main_parser: argparse.ArgumentParser = build_parser()
    parsed_args: argparse.Namespace = main_parser.parse_args()
    if not parsed_args.command:
        main_parser.print_help()
        raise SystemExit(1)
    parsed_args.func(parsed_args)
