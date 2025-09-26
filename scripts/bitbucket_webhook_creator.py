#!/usr/bin/env python3

import argparse
import http.client
import json
import os
import sys
import urllib.parse


def _make_bitbucket_request(method, url, token, headers=None, body=None):
    """
    Make a Bitbucket API request using only the standard library.

    Args:
        method: HTTP method (e.g., "GET", "POST").
        url: Full URL to request.
        token: Bitbucket API token.
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

    req_headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
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


def get_repo_hooks(token, workspace, repo_slug):
    """
    Get the list of webhooks for a Bitbucket repository.

    Args:
        token: Bitbucket API token.
        workspace: Bitbucket workspace (usually the team or user).
        repo_slug: Repository slug.

    Returns:
        List of webhook objects.

    Raises:
        Exception: If fetching webhooks fails.
    """
    url = f"https://api.bitbucket.org/2.0/repositories/{workspace}/{repo_slug}/hooks"
    hooks = []
    next_url = url
    while next_url:
        status, headers, resp_json, resp_text = _make_bitbucket_request("GET", next_url, token)
        if status != 200:
            raise Exception(f"Failed to fetch webhooks: {status} {resp_text}")
        resp_json = resp_json or {}
        if "values" in resp_json:
            hooks.extend(resp_json["values"])
        next_url = resp_json.get("next")
    return hooks


def create_repo_hook(token, workspace, repo_slug, hook_url, events, description=None, active=True):
    """
    Create a webhook for a Bitbucket repository.

    Args:
        token: Bitbucket API token.
        workspace: Bitbucket workspace.
        repo_slug: Repository slug.
        hook_url: The webhook URL.
        events: List of event names to subscribe to.
        description: Optional description for the webhook.
        active: Whether the webhook should be active.

    Returns:
        The created webhook object.

    Raises:
        Exception: If webhook creation fails.
    """
    api_url = f"https://api.bitbucket.org/2.0/repositories/{workspace}/{repo_slug}/hooks"
    data = {
        "description": description or "Neo Webhook",
        "url": hook_url,
        "active": active,
        "events": events,
    }
    body = json.dumps(data)
    status, headers, resp_json, resp_text = _make_bitbucket_request("POST", api_url, token, body=body)
    if status in (201, 200) and resp_json:
        return resp_json
    else:
        raise Exception(f"Failed to create webhook: {status} {resp_text}")


def parse_repo_full_name(repo_full_name):
    """
    Parse a Bitbucket repository full name into workspace and repo_slug.

    Args:
        repo_full_name: String in the form "workspace/repo-slug".

    Returns:
        (workspace, repo_slug) tuple.

    Raises:
        ValueError: If the format is invalid.
    """
    if "/" not in repo_full_name:
        raise ValueError(f"Invalid repository name '{repo_full_name}'. Expected format: 'workspace/repo-slug'")
    workspace, repo_slug = repo_full_name.split("/", 1)
    return workspace, repo_slug


def main():
    """
    Bitbucket Webhook Creator Script

    This script allows you to create webhooks on one or more Bitbucket repositories
    using a configuration file. It is designed to be easy to use, even for those
    with limited Python experience, and does not require any third-party packages.

    Features:
    - Reads a JSON config file describing which webhooks to create for which repositories.
    - Authenticates with Bitbucket using an App Password or OAuth token.
    - Checks if a webhook with the same URL already exists before creating.
    - Creates any missing webhooks as specified.

    Prerequisites:
    - You need a Bitbucket username and an App Password with the following permissions:
        - "Repository:Admin"
        - "Account:Read"
        - "Pull requests:Read"
        - "Webhook:Read and write"
      See: https://support.atlassian.com/bitbucket-cloud/docs/app-passwords/
    - You need a JSON configuration file describing which webhooks to create for which repositories.

    Example config file (bitbucket_webhooks.json):

        {
          "workspace/repo-slug": [
            {
              "url": "https://dev.neo.sagittal.ai/bitbucket/pr_comment/neo_pat_xxx/project-yyy",
              "config": {
                "id": null,
                "name": "Comment on PR",
                "events": [
                  "pullrequest:comment_created"
                ]
              }
            },
            {
              "url": "https://dev.neo.sagittal.ai/bitbucket/pr_review/neo_pat_xxx/project-yyy",
              "config": {
                "id": null,
                "name": "Review PR",
                "events": [
                  "pullrequest:updated",
                  "pullrequest:created"
                ]
              }
            }
          ]
        }

    How to use:

    1. Save your config file (e.g., bitbucket_webhooks.json) in the same directory as this script.

    2. Run the script from the command line:

       python scripts/bitbucket_webhook_creator.py bitbucket_webhooks.json --username YOUR_BITBUCKET_USERNAME --token YOUR_API_TOKEN

       - Replace "bitbucket_webhooks.json" with your config file path.
       - Replace "YOUR_BITBUCKET_USERNAME" and "YOUR_API_TOKEN" with your Bitbucket credentials.

       Alternatively, you can set your credentials as environment variables:

       export BITBUCKET_USERNAME=your_username
       export BITBUCKET_API_TOKEN=your_api_token
       python scripts/bitbucket_webhook_creator.py

    3. The script will:
       - Authenticate with Bitbucket.
       - For each repository in your config, check if the webhook already exists (by URL).
       - Create any missing webhooks as specified.

    Notes:
    - This script uses only the Python standard library.
    - If you see errors about authentication or permissions, check your credentials and repository access.
    - You must have admin rights on the repository to add webhooks.

    Author: Neo @ Sagittal.ai
    """
    parser = argparse.ArgumentParser(description=main.__doc__, formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument(
        "config_file",
        nargs="?",
        default="bitbucket_webhooks.json",
        type=str,
        help="Path to the JSON file containing webhook configuration. Defaults to 'bitbucket_webhooks.json'.",
    )
    parser.add_argument(
        "--token",
        "-t",
        type=str,
        default=None,
        help="Bitbucket API token. If not provided, will use BITBUCKET_API_TOKEN environment variable.",
    )
    args = parser.parse_args()

    config_file = args.config_file
    token = args.token or os.environ.get("BITBUCKET_API_TOKEN")

    if not token:
        print(
            "Error: Bitbucket API token must be provided. Use --token or set BITBUCKET_API_TOKEN env variables.",
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

    # Iterate through repositories in config
    for repo_full_name, webhooks in config.items():
        print(f"\nProcessing repository: {repo_full_name}")
        try:
            workspace, repo_slug = parse_repo_full_name(repo_full_name)
        except ValueError as e:
            print(f"  [ERROR] {e}", file=sys.stderr)
            continue

        # Get existing webhooks to avoid duplicates
        try:
            existing_hooks = get_repo_hooks(token, workspace, repo_slug)
        except Exception as e:
            print(f"  [ERROR] Could not fetch existing webhooks: {e}", file=sys.stderr)
            continue

        for webhook in webhooks:
            url = webhook.get("url")
            config_obj = webhook.get("config", {})
            events = config_obj.get("events", [])
            name = config_obj.get("name", "Neo Webhook")

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
                create_repo_hook(
                    token,
                    workspace,
                    repo_slug,
                    url,
                    events,
                    description=name,
                    active=True,
                )
                print(f"  [OK] Created webhook '{name}' for events: {', '.join(events)}")
            except Exception as e:
                print(f"  [ERROR] Failed to create webhook '{name}': {e}", file=sys.stderr)

    print("\nDone.")


if __name__ == "__main__":
    main()
