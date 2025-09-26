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


def delete_hook(token, workspace, repo_slug, hook_uuid):
    """
    Delete a webhook from a Bitbucket repository.

    Args:
        token: Bitbucket API token.
        workspace: Bitbucket workspace.
        repo_slug: Repository slug.
        hook_uuid: UUID of the webhook to delete.

    Raises:
        Exception: If deletion fails.
    """
    url = f"https://api.bitbucket.org/2.0/repositories/{workspace}/{repo_slug}/hooks/{hook_uuid}"
    status, headers, resp_json, resp_text = _make_bitbucket_request("DELETE", url, token)
    if status != 204:
        raise Exception(f"Failed to delete webhook: {status} {resp_text}")


def get_workspace_repos(token, workspace):
    """
    Get the list of repositories for a Bitbucket workspace.

    Args:
        token: Bitbucket API token.
        workspace: Bitbucket workspace (usually the team or user).

    Returns:
        List of repository slugs.

    Raises:
        Exception: If fetching repositories fails.
    """
    url = f"https://api.bitbucket.org/2.0/repositories/{workspace}"
    repos = []
    next_url = url
    while next_url:
        status, headers, resp_json, resp_text = _make_bitbucket_request("GET", next_url, token)
        if status != 200:
            raise Exception(f"Failed to fetch repositories: {status} {resp_text}")
        resp_json = resp_json or {}
        if "values" in resp_json:
            repos.extend([repo["slug"] for repo in resp_json["values"]])
        next_url = resp_json.get("next")
    return repos


def main():
    parser = argparse.ArgumentParser(description="Manage Bitbucket webhooks.")
    parser.add_argument("workspace", help="The Bitbucket workspace name.")
    parser.add_argument(
        "--token",
        "-t",
        type=str,
        default=None,
        help="Bitbucket API token. If not provided, will use BITBUCKET_API_TOKEN environment variable.",
    )
    parser.add_argument("--delete", action="store_true", help="Delete the matching webhooks")
    args = parser.parse_args()

    token = args.token or os.environ.get("BITBUCKET_API_TOKEN")

    if not token:
        print(
            "Error: Bitbucket API token must be provided. Use --token or set BITBUCKET_API_TOKEN env variables.",
            file=sys.stderr,
        )
        sys.exit(1)

    try:
        repos = get_workspace_repos(token, args.workspace)
    except Exception as e:
        print(f"[ERROR] Could not fetch repositories: {e}", file=sys.stderr)
        sys.exit(1)

    neo_url = "https://dev.neo.sagittal.ai"
    for repo_slug in repos:
        try:
            hooks = get_repo_hooks(token, args.workspace, repo_slug)
        except Exception as e:
            print(f"[ERROR] Could not fetch webhooks for repository {repo_slug}: {e}", file=sys.stderr)
            continue

        matching_hooks = [hook for hook in hooks if neo_url in hook.get("url", "")]

        if not matching_hooks:
            print(f"No matching webhooks found for repository {repo_slug}.")
            continue

        print(f"Matching webhooks for repository {repo_slug}:")
        for hook in matching_hooks:
            print(f"  - {hook['uuid']}: {hook['url']}")

        if args.delete:
            print("\n\n")
            for hook in matching_hooks:
                try:
                    delete_hook(token, args.workspace, repo_slug, hook["uuid"])
                    print(f"  [OK] Deleted webhook {hook['uuid']} from repository {repo_slug}")
                except Exception as e:
                    print(
                        f"  [ERROR] Failed to delete webhook {hook['uuid']} from repository {repo_slug}: {e}",
                        file=sys.stderr,
                    )


if __name__ == "__main__":
    main()
