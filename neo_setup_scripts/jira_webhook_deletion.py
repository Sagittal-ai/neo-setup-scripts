import argparse
import base64
import http.client
import json
import os
import sys
import urllib.parse


def _make_jira_request(method, url, username, token, headers=None, body=None):
    """
    Make a Jira API request using only the standard library.

    Args:
        method: HTTP method (e.g., "GET", "POST").
        url: Full URL to request.
        username: Jira username.
        token: Jira API token.
        headers: Optional additional headers.
        body: Optional request body (JSON string).

    Returns:
        Tuple containing:
            - status_code (int)
            - response_headers (dict)
            - response_json (dict or list or None)
            - response_text (str)
    """
    parsed_url = urllib.parse.urlparse(url)
    conn = http.client.HTTPSConnection(parsed_url.hostname, 443)
    path = parsed_url.path
    if parsed_url.query:
        path += "?" + parsed_url.query

    auth_str = f"{username}:{token}"
    auth_bytes = auth_str.encode("utf-8")
    auth_b64 = base64.b64encode(auth_bytes).decode("utf-8")

    req_headers = {
        "Authorization": f"Basic {auth_b64}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "jira-webhook-deletion-script",
    }
    if headers:
        req_headers.update(headers)
    if body is not None:
        body = body.encode("utf-8")

    conn.request(method, path, body=body, headers=req_headers)
    resp = conn.getresponse()
    resp_text = resp.read().decode("utf-8")
    try:
        resp_json = json.loads(resp_text)
    except Exception:
        resp_json = None

    return resp.status, dict(resp.getheaders()), resp_json, resp_text


def get_jira_hooks(username, token, base_url):
    """
    Retrieve existing webhooks for a Jira instance.

    Args:
        username: Jira username.
        token: Jira API token.
        base_url: Base URL of the Jira instance.

    Returns:
        List of existing webhooks.

    Raises:
        Exception: If fetching webhooks fails.
    """
    api_url = f"{base_url}/rest/webhooks/1.0/webhook"
    status, headers, resp_json, resp_text = _make_jira_request("GET", api_url, username, token)
    if status == 200:
        return resp_json or []
    else:
        raise Exception(f"Failed to fetch webhooks: {status} {resp_text}")


def delete_hook(username, token, base_url, hook_id):
    """
    Delete a webhook from a Jira instance.

    Args:
        username: Jira username.
        token: Jira API token.
        base_url: Base URL of the Jira instance.
        hook_id: ID of the webhook to delete.

    Raises:
        Exception: If deletion fails.
    """
    url = f"{base_url}/rest/webhooks/1.0/webhook/{hook_id}"
    status, headers, resp_json, resp_text = _make_jira_request("DELETE", url, username, token)
    if status != 204:
        raise Exception(f"Failed to delete webhook: {status} {resp_text}")


def main():
    parser = argparse.ArgumentParser(description="Manage Jira webhooks.")
    parser.add_argument(
        "--username",
        "-u",
        type=str,
        default=None,
        help="Jira username. If not provided, will use JIRA_USERNAME environment variable.",
    )
    parser.add_argument(
        "--token",
        "-t",
        type=str,
        default=None,
        help="Jira API token. If not provided, will use JIRA_TOKEN environment variable.",
    )
    parser.add_argument(
        "--base-url",
        "-b",
        type=str,
        default=None,
        help="Base URL of the Jira instance. If not provided, will use JIRA_BASE_URL environment variable.",
    )
    parser.add_argument("--delete", action="store_true", help="Delete the matching webhooks")
    args = parser.parse_args()

    username = args.username or os.environ.get("JIRA_USERNAME")
    token = args.token or os.environ.get("JIRA_TOKEN")
    base_url = args.base_url or os.environ.get("JIRA_BASE_URL")

    if not username or not token or not base_url:
        print(
            "Error: Jira username, API token, and base URL must be provided. Use --username/--token/--base-url or set JIRA_USERNAME/JIRA_TOKEN/JIRA_BASE_URL env variables.",
            file=sys.stderr,
        )
        sys.exit(1)

    try:
        hooks = get_jira_hooks(username, token, base_url)
    except Exception as e:
        print(f"[ERROR] Could not fetch webhooks: {e}", file=sys.stderr)
        sys.exit(1)

    neo_url = "https://dev.neo.sagittal.ai"
    matching_hooks = [hook for hook in hooks if neo_url in hook.get("url", "")]

    if not matching_hooks:
        print("No matching webhooks found.")
        return

    print("Matching webhooks:")
    for hook in matching_hooks:
        print(f"  - {hook['id']}: {hook['url']}")

    if args.delete:
        print("\n\n")
        for hook in matching_hooks:
            try:
                delete_hook(username, token, base_url, hook["id"])
                print(f"  [OK] Deleted webhook {hook['id']}")
            except Exception as e:
                print(f"  [ERROR] Failed to delete webhook {hook['id']}: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
