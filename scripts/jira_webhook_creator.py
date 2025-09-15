#!/usr/bin/env python3

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

    # Jira uses HTTP Basic Auth with username:token
    auth_str = f"{username}:{token}"
    auth_bytes = auth_str.encode("utf-8")
    auth_b64 = base64.b64encode(auth_bytes).decode("utf-8")

    req_headers = {
        "Authorization": f"Basic {auth_b64}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "jira-webhook-creator-script",
    }
    if headers:
        req_headers.update(headers)
    if body is not None and isinstance(body, str):
        body = body.encode("utf-8")

    conn.request(method, path, body=body, headers=req_headers)
    resp = conn.getresponse()
    resp_text = resp.read().decode("utf-8")
    try:
        resp_json = json.loads(resp_text)
    except Exception:
        resp_json = None

    return resp.status, dict(resp.getheaders()), resp_json, resp_text


def create_jira_webhook(username, token, base_url, project_key, hook_url, events, jql, description=None, active=True):
    """
    Create a webhook for a Jira project.

    Args:
        username: Jira username.
        token: Jira API token.
        base_url: Base URL of the Jira instance.
        project_key: Project key for the Jira project.
        hook_url: The webhook URL.
        events: List of event names to subscribe to.
        jql: JQL query to filter events.
        description: Optional description for the webhook.
        active: Whether the webhook should be active.

    Returns:
        The created webhook object.

    Raises:
        Exception: If webhook creation fails.
    """
    api_url = f"{base_url}/rest/webhooks/1.0/webhook"  # type: ignore
    data = {
        "name": description or "Neo Webhook",
        "url": hook_url,
        "events": events,
        "filters": {"issue-related-events-section": jql},
        "enabled": active,
    }
    body = json.dumps(data)
    status, headers, resp_json, resp_text = _make_jira_request("POST", api_url, username, token, body=body)
    if status in (201, 200) and resp_json:
        return resp_json
    else:
        raise Exception(f"Failed to create webhook: {status} {resp_text}")


def main():
    """
    Jira Webhook Creator Script

    This script allows you to create webhooks on one or more Jira projects
    using a configuration file. It is designed to be easy to use, even for those
    with limited Python experience, and does not require any third-party packages.

    Features:
    - Reads a JSON config file describing which webhooks to create for which projects.
    - Authenticates with Jira using an API token.
    - Checks if a webhook with the same URL already exists before creating.
    - Creates any missing webhooks as specified.

    Prerequisites:
    - You need a Jira username and an API token with the necessary permissions.
    - You need a JSON configuration file describing which webhooks to create for which projects.

    Example config file (jira_webhooks.json):

        {
          "PROJECT_KEY": [
            {
              "url": "https://dev.neo.sagittal.ai/jira/wi_comment/neo_pat_xxx/project-yyy",
              "config": {
                "id": null,
                "name": "Comment on Work Item",
                "events": [
                  "jira:issue_created",
                  "jira:issue_updated"
                ],
                "jql": "project = PROJECT_KEY"
              }
            }
          ]
        }

    How to use:

    1. Save your config file (e.g., jira_webhooks.json) in the same directory as this script.

    2. Run the script from the command line:

       python scripts/jira_webhook_creator.py jira_webhooks.json --username YOUR_JIRA_USERNAME --api-token YOUR_JIRA_token --base-url YOUR_JIRA_BASE_URL

       - Replace "jira_webhooks.json" with your config file path.
       - Replace "YOUR_JIRA_USERNAME", "YOUR_JIRA_token", and "YOUR_JIRA_BASE_URL" with your Jira credentials and instance URL.

       Alternatively, you can set your credentials as environment variables:

       export JIRA_USERNAME=your_username
       export JIRA_TOKEN=your_token
       export JIRA_BASE_URL=your_base_url
       python scripts/jira_webhook_creator.py

    3. The script will:
       - Authenticate with Jira.
       - For each project in your config, check if the webhook already exists (by URL).
       - Create any missing webhooks as specified.

    Notes:
    - This script uses only the Python standard library.
    - If you see errors about authentication or permissions, check your credentials and project access.
    - You must have admin rights on the project to add webhooks.

    Author: Neo @ Sagittal.ai
    """
    parser = argparse.ArgumentParser(description=main.__doc__, formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument(
        "config_file",
        nargs="?",
        default="webhooks.json",
        type=str,
        help="Path to the JSON file containing webhook configuration. Defaults to 'jira_webhooks.json'.",
    )
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
        help="Jira API token. If not provided, will use JIRA_token environment variable.",
    )
    parser.add_argument(
        "--base-url",
        "-b",
        type=str,
        default=None,
        help="Base URL of the Jira instance. If not provided, will use JIRA_BASE_URL environment variable.",
    )
    args = parser.parse_args()

    config_file = args.config_file
    username = args.username or os.environ.get("JIRA_USERNAME")
    token = args.token or os.environ.get("JIRA_TOKEN")
    base_url = args.base_url or os.environ.get("JIRA_BASE_URL")

    if not token or not base_url:
        print(
            "Error: Jira username, API token, and base URL must be provided. Use --username/--token/--base-url or set JIRA_USERNAME/JIRA_TOKEN/JIRA_BASE_URL env variables.",
            file=sys.stderr,
        )
        sys.exit(1)

    # Load config file
    try:
        with open(config_file, "r", encoding="utf-8") as f:
            config = json.load(f)
    except Exception as e:
        print(f"Error reading config file: {e}", file=sys.stderr)
        sys.exit(1)

    # Iterate through projects in config
    for project_key, webhooks in config.items():
        print(f"\nProcessing project: {project_key}")

        # Get existing webhooks to avoid duplicates
        try:
            existing_hooks = get_jira_hooks(username, token, base_url, project_key)
        except Exception as e:
            print(f"  [ERROR] Could not fetch existing webhooks: {e}", file=sys.stderr)
            continue

        for webhook in webhooks:
            url = webhook.get("url")
            config_obj = webhook.get("config", {})
            events = config_obj.get("events", [])
            name = config_obj.get("name", "Neo Webhook")
            jql = config_obj.get("jql", f"project = {project_key}")

            # Check if webhook with same URL already exists
            already_exists = False
            for hook in existing_hooks:
                if hook.get("url") == url:
                    already_exists = True
                    print(f"  [SKIP] Webhook for URL '{url}' already exists.")
                    break

            if already_exists:
                continue

            # Attempt to create webhook
            try:
                create_jira_webhook(
                    username,
                    token,
                    base_url,
                    project_key,
                    url,
                    events,
                    jql,
                    description=name,
                    active=True,
                )
                print(f"  [OK] Created webhook '{name}' for events: {', '.join(events)}")
            except Exception as e:
                print(f"  [ERROR] Failed to create webhook '{name}': {e}", file=sys.stderr)

    print("\nDone.")


def get_jira_hooks(username, token, base_url, project_key):
    """
    Retrieve existing webhooks for a Jira project.

    Args:
        username: Jira username.
        token: Jira API token.
        base_url: Base URL of the Jira instance.
        project_key: Project key for the Jira project.

    Returns:
        List of existing webhooks.

    Raises:
        Exception: If fetching webhooks fails.
    """
    api_url = f"{base_url}/rest/webhooks/1.0/webhook"  # type: ignore
    status, headers, resp_json, resp_text = _make_jira_request("GET", api_url, username, token)
    if status in (200,):
        return resp_json or []
    else:
        raise Exception(f"Failed to fetch webhooks: {status} {resp_text}")


if __name__ == "__main__":
    main()