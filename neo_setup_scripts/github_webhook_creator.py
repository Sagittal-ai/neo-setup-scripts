import argparse
import http.client
import json
import os
import sys
import urllib.parse


def _make_github_request(method, url, token, headers=None, body=None):
    """
    Make a GitHub API request using only the standard library.
    Args:
        method: HTTP method (e.g., "GET", "POST").
        url: Full URL to request.
        token: GitHub personal access token.
        headers: Optional additional headers.
        body: Optional request body (JSON string).
    Returns:
        Tuple containing:
            - status_code (int)
            - response_headers (dict)
            - response_json (dict or list or None)
            - response_text (str)
            - links_dict (dict for pagination)
    """
    parsed_url = urllib.parse.urlparse(url)
    conn = http.client.HTTPSConnection(parsed_url.hostname, 443)
    path = parsed_url.path
    if parsed_url.query:
        path += "?" + parsed_url.query

    req_headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "github-webhook-creator-script",
    }
    if headers:
        req_headers.update(headers)
    if body is not None:
        req_headers["Content-Type"] = "application/json"
        body = body.encode("utf-8")

    conn.request(method, path, body=body, headers=req_headers)
    resp = conn.getresponse()
    resp_text = resp.read().decode("utf-8")
    try:
        resp_json = json.loads(resp_text)
    except Exception:
        resp_json = None

    # Parse Link header for pagination
    links = {}
    link_header = resp.getheader("Link")
    if link_header:
        parts = link_header.split(",")
        for part in parts:
            section = part.strip().split(";")
            if len(section) == 2:
                url_part = section[0].strip()[1:-1]
                rel_part = section[1].strip()
                if rel_part.startswith('rel="') and rel_part.endswith('"'):
                    rel = rel_part[5:-1]
                    links[rel] = {"url": url_part}
    return resp.status, dict(resp.getheaders()), resp_json, resp_text, links


def get_authenticated_user(token):
    """
    Authenticate with GitHub and return the username.
    Args:
        token: GitHub personal access token.
    Returns:
        The authenticated user's login name.
    Raises:
        Exception: If authentication fails.
    """

    url = "https://api.github.com/user"
    status, headers, resp_json, resp_text, _ = _make_github_request("GET", url, token)
    if status == 200 and resp_json and "login" in resp_json:
        return resp_json["login"]
    else:
        raise Exception(f"GitHub authentication failed: {status} {resp_text}")


def get_repo_hooks(token, repo_full_name):
    """
    Retrieve all webhooks for a given repository.
    Args:
        token: GitHub personal access token.
        repo_full_name: Full repository name (e.g., "username/repo").
    Returns:
        List of webhook objects.
    Raises:
        Exception: If unable to fetch webhooks.
    """

    hooks = []
    url = f"https://api.github.com/repos/{repo_full_name}/hooks"
    while url:
        status, headers, resp_json, resp_text, links = _make_github_request("GET", url, token)
        if status == 200:
            resp_json = resp_json or []
            if isinstance(resp_json, list):
                hooks.extend(resp_json)
            if "next" in links:
                url = links["next"]["url"]
            else:
                url = None
        else:
            raise Exception(f"Could not fetch webhooks: {status} {resp_text}")
    return hooks


def create_repo_hook(token, repo_full_name, hook_config, events, active=True):
    """
    Create a webhook for a repository.
    Args:
        token: GitHub personal access token.
        repo_full_name: Full repository name (e.g., "username/repo").
        hook_config: Webhook configuration dictionary.
        events: List of event names to subscribe to.
        active: Whether the webhook should be active.
    Returns:
        The created webhook object.
    Raises:
        Exception: If webhook creation fails.
    """

    url = f"https://api.github.com/repos/{repo_full_name}/hooks"
    data = {"name": "web", "config": hook_config, "events": events, "active": active}
    body = json.dumps(data)
    status, headers, resp_json, resp_text, _ = _make_github_request("POST", url, token, body=body)
    if status in (201, 200) and resp_json:
        return resp_json
    else:
        raise Exception(f"Failed to create webhook: {status} {resp_text}")


def main():
    """
    Create GitHub webhooks for repositories as specified in a JSON config file.

    This script helps you automatically create webhooks on one or more GitHub repositories
    using a configuration file. It is designed to be easy to use, even if you are new to Python.

    Prerequisites:
    - You need a GitHub personal access token (PAT) with "repo" and "admin:repo_hook" permissions.
      You can create one at https://github.com/settings/tokens
    - You need a JSON configuration file describing which webhooks to create for which repositories.

    How to use:

    1. Ensure the webhooks.json file you've been given is in the same directory as the script.

    2. Run the script from the command line:

       python scripts/github_webhook_creator.py webhooks.json --token YOUR_GITHUB_TOKEN

       - Replace "webhooks.json" with the path to your config file.
       - Replace "YOUR_GITHUB_TOKEN" with your personal access token.

       Alternatively, you can set your token as an environment variable:

       export GITHUB_TOKEN=YOUR_GITHUB_TOKEN
       python scripts/github_webhook_creator.py webhooks.json

    3. The script will:
       - Authenticate with GitHub.
       - For each repository in your config, check if the webhook already exists (by URL).
       - Create any missing webhooks as specified.

    Notes:
    - You do NOT need to install any extra Python packages; this script uses only the standard library.
    - If you see errors about authentication or permissions, check your token and repository access.
    - If you are not the owner of a repository, you must have admin rights to add webhooks.

    Example command:

        # With default json file and token in environment variable
        python scripts/github_webhook_creator.py

        # With differently names json file and token as a command line argument
        python scripts/github_webhook_creator.py my_webhooks.json --token ghp_XXXXXXXXXXXXXXXXXXXX

    """
    parser = argparse.ArgumentParser(description=main.__doc__, formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument(
        "config_file",
        nargs="?",
        default="webhooks.json",
        type=str,
        help="Path to the JSON file containing webhook configuration. Defaults to 'webhooks.json'.",
    )
    parser.add_argument(
        "--token",
        "-t",
        type=str,
        default=None,
        help="GitHub personal access token. If not provided, will use GITHUB_TOKEN environment variable.",
    )
    args = parser.parse_args()

    config_file = args.config_file
    token = args.token

    # Get token from argument or environment
    github_token = token or os.environ.get("GITHUB_TOKEN")
    if not github_token:
        print("Error: GitHub token not provided. Use --token or set GITHUB_TOKEN env variable.", file=sys.stderr)
        sys.exit(1)

    # Load config file
    try:
        with open(config_file, "r", encoding="utf-8") as f:
            config = json.load(f)
    except Exception as e:
        print(f"Error reading config file: {e}", file=sys.stderr)
        sys.exit(1)

    # Connect to GitHub (authenticate)
    try:
        user = get_authenticated_user(github_token)
    except Exception as e:
        print(f"Error authenticating with GitHub: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Authenticated as: {user}")

    # Iterate through repositories in config
    for repo_full_name, webhooks in config.items():
        print(f"\nProcessing repository: {repo_full_name}")
        # Get existing webhooks to avoid duplicates
        try:
            existing_hooks = get_repo_hooks(github_token, repo_full_name)
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
                if hook.get("config", {}).get("url") == url:
                    already_exists = True
                    print(f"  [SKIP] Webhook for URL '{url}' already exists.")
                    break

            if already_exists:
                continue

            # Prepare webhook config
            hook_config = {
                "url": url,
                "content_type": "json",
            }

            # Attempt to create webhook
            try:
                create_repo_hook(
                    github_token,
                    repo_full_name,
                    hook_config,
                    events,
                    active=True,
                )
                print(f"  [OK] Created webhook '{name}' for events: {', '.join(events)}")

            except Exception as e:
                print(f"  [ERROR] Failed to create webhook '{name}': {e}", file=sys.stderr)

    print("\nDone.")


if __name__ == "__main__":
    main()
