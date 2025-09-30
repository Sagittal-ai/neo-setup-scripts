#!/usr/bin/env python3

import argparse
import http.client
import json
import os
import sys
import urllib.parse


def _make_gitlab_request(method, url, token, headers=None, body=None):
    """
    Make a GitLab API request using only the standard library.

    Args:
        method: HTTP method (e.g., "GET", "POST").
        url: Full URL to request.
        token: GitLab personal access token.
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
        "User-Agent": "gitlab-webhook-creator-script",
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


def get_authenticated_user(token, base_url):
    """
    Get the authenticated user to verify the token works.

    Args:
        token: GitLab personal access token.
        base_url: Base URL of the GitLab instance.

    Returns:
        Username of the authenticated user.

    Raises:
        Exception: If authentication fails.
    """
    api_url = f"{base_url}/api/v4/user"
    status, headers, resp_json, resp_text = _make_gitlab_request("GET", api_url, token)
    if status == 200 and resp_json:
        return resp_json["username"]
    else:
        raise Exception(f"Authentication failed: {status} {resp_text}")


def get_project_hooks(token, base_url, project_id):
    """
    Get existing webhooks for a GitLab project.

    Args:
        token: GitLab personal access token.
        base_url: Base URL of the GitLab instance.
        project_id: Project ID or path (URL-encoded).

    Returns:
        List of existing webhooks.

    Raises:
        Exception: If the request fails.
    """
    api_url = f"{base_url}/api/v4/projects/{project_id}/hooks"
    status, headers, resp_json, resp_text = _make_gitlab_request("GET", api_url, token)
    if status == 200:
        return resp_json or []
    else:
        raise Exception(f"Failed to get project hooks: {status} {resp_text}")


def create_project_hook(token, base_url, project_id, hook_url, config):
    """
    Create a webhook for a GitLab project.

    Args:
        token: GitLab personal access token.
        base_url: Base URL of the GitLab instance.
        project_id: Project ID or path (URL-encoded).
        hook_url: URL for the webhook.
        config: Webhook configuration dict.

    Returns:
        Created webhook data.

    Raises:
        Exception: If the request fails.
    """
    api_url = f"{base_url}/api/v4/projects/{project_id}/hooks"

    # Map our config to GitLab API parameters
    data = {
        "url": hook_url,
        "push_events": config.get("push_events", False),
        "issues_events": config.get("issues_events", False),
        "merge_requests_events": config.get("merge_requests_events", False),
        "tag_push_events": config.get("tag_push_events", False),
        "note_events": config.get("comment_events", False),
        "job_events": config.get("job_events", False),
        "pipeline_events": config.get("pipeline_events", False),
        "wiki_page_events": config.get("wiki_page_events", False),
        "deployment_events": config.get("deployment_events", False),
        "releases_events": config.get("releases_events", False),
        "subgroup_events": config.get("subgroup_events", False),
        "enable_ssl_verification": config.get("enable_ssl_verification", True),
        "token": config.get("token", ""),
        "push_events_branch_filter": config.get("push_events_branch_filter", ""),
    }

    body = json.dumps(data)
    status, headers, resp_json, resp_text = _make_gitlab_request("POST", api_url, token, body=body)
    if status in (201, 200) and resp_json:
        return resp_json
    else:
        raise Exception(f"Failed to create webhook: {status} {resp_text}")


def parse_project_path(project_path):
    """
    Parse a project path into namespace and project name.

    Args:
        project_path: Full project path (e.g., "namespace/project" or "group/subgroup/project").

    Returns:
        Tuple of (namespace, project_name).

    Raises:
        ValueError: If the project path format is invalid.
    """
    parts = project_path.split("/")
    if len(parts) < 2:
        raise ValueError(
            f"Invalid project path format: {project_path}. Expected 'namespace/project' or 'group/subgroup/project'."
        )

    # For GitLab, we can have nested groups, so everything except the last part is the namespace
    project_name = parts[-1]
    namespace = "/".join(parts[:-1])

    return namespace, project_name


def main():
    """
    GitLab Webhook Creator Script

    This script allows you to create webhooks on one or more GitLab projects
    using a configuration file. It is designed to be easy to use, even for those
    with limited Python experience, and does not require any third-party packages.

    Features:
    - Reads a JSON config file describing which webhooks to create for which projects.
    - Authenticates with GitLab using a personal access token.
    - Checks if a webhook with the same URL already exists before creating.
    - Creates any missing webhooks as specified.

    Prerequisites:
    - You need a GitLab personal access token with the necessary permissions (api scope).
    - You need a JSON configuration file describing which webhooks to create for which projects.

    Example config file (webhooks.json):

        {
          "namespace/project": [
            {
              "url": "https://dev.neo.sagittal.ai/gitlab/pr_comment/neo_pat_xxx/project-yyy",
              "config": {
                "id": null,
                "name": "Comment on Work Item",
                "comment_events": true,
                "merge_requests_events": false,
                "pipeline_events": false
              }
            }
          ]
        }

    How to use:

    1. Save your config file (e.g., webhooks.json) in the same directory as this script.

    2. Run the script from the command line:

       python scripts/gitlab_webhook_creator.py webhooks.json --token YOUR_GITLAB_TOKEN --base-url YOUR_GITLAB_BASE_URL

       - Replace "webhooks.json" with your config file path.
       - Replace "YOUR_GITLAB_TOKEN" and "YOUR_GITLAB_BASE_URL" with your GitLab credentials and instance URL.

       Alternatively, you can set your credentials as environment variables:

       export GITLAB_TOKEN=your_token
       export GITLAB_BASE_URL=your_base_url
       python scripts/gitlab_webhook_creator.py webhooks.json

    3. The script will:
       - Authenticate with GitLab.
       - For each project in your config, check if the webhook already exists (by URL).
       - Create any missing webhooks as specified.

    Notes:
    - This script uses only the Python standard library.
    - If you see errors about authentication or permissions, check your token and project access.
    - You must have maintainer or owner rights on the project to add webhooks.
    - For GitLab.com, use https://gitlab.com as the base URL.
    - For self-hosted GitLab instances, use your instance URL (e.g., https://gitlab.example.com).

    Author: Neo @ Sagittal.ai
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
        help="GitLab personal access token. If not provided, will use GITLAB_TOKEN environment variable.",
    )
    parser.add_argument(
        "--base-url",
        "-b",
        type=str,
        default=None,
        help="Base URL of the GitLab instance (e.g., https://gitlab.com). If not provided, will use GITLAB_BASE_URL environment variable.",
    )
    args = parser.parse_args()

    config_file = args.config_file
    gitlab_token = args.token or os.environ.get("GITLAB_TOKEN")
    base_url = args.base_url or os.environ.get("GITLAB_BASE_URL", "https://gitlab.com")

    if not gitlab_token:
        print("Error: GitLab token not provided. Use --token or set GITLAB_TOKEN env variable.", file=sys.stderr)
        sys.exit(1)

    # Remove trailing slash from base_url if present
    base_url = base_url.rstrip("/")

    # Load config file
    try:
        with open(config_file, "r", encoding="utf-8") as f:
            config = json.load(f)
    except Exception as e:
        print(f"Error reading config file: {e}", file=sys.stderr)
        sys.exit(1)

    # Connect to GitLab (authenticate)
    try:
        user = get_authenticated_user(gitlab_token, base_url)
    except Exception as e:
        print(f"Error authenticating with GitLab: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Authenticated as: {user}")

    # Iterate through projects in config
    for project_path, webhooks in config.items():
        print(f"\nProcessing project: {project_path}")

        # URL-encode the project path for API calls
        project_id = urllib.parse.quote(project_path, safe="")

        # Get existing webhooks to avoid duplicates
        try:
            existing_hooks = get_project_hooks(gitlab_token, base_url, project_id)
        except Exception as e:
            print(f"  [ERROR] Could not fetch existing webhooks: {e}", file=sys.stderr)
            continue

        for webhook in webhooks:
            url = webhook.get("url")
            config_obj = webhook.get("config", {})
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
                create_project_hook(
                    gitlab_token,
                    base_url,
                    project_id,
                    url,
                    config_obj,
                )

                # Build event list for display
                events = []
                if config_obj.get("comment_events"):
                    events.append("note_events")
                if config_obj.get("merge_requests_events"):
                    events.append("merge_requests_events")
                if config_obj.get("pipeline_events"):
                    events.append("pipeline_events")
                if config_obj.get("push_events"):
                    events.append("push_events")
                if config_obj.get("issues_events"):
                    events.append("issues_events")

                events_str = ", ".join(events) if events else "default events"
                print(f"  [OK] Created webhook '{name}' for events: {events_str}")
            except Exception as e:
                print(f"  [ERROR] Failed to create webhook '{name}': {e}", file=sys.stderr)

    print("\nDone.")


if __name__ == "__main__":
    main()
