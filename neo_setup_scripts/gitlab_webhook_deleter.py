import argparse
import http.client
import json
import os
import sys
import urllib.parse


def _make_gitlab_request(
    method: str, url: str, token: str, headers: dict | None = None, body: str | None = None
) -> tuple[int, dict, dict | list | None, str]:
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
    parsed_url: urllib.parse.ParseResult = urllib.parse.urlparse(url)
    hostname: str = parsed_url.hostname or ""
    if not hostname:
        raise ValueError(f"Invalid URL, could not determine hostname: {url}")
    conn: http.client.HTTPSConnection = http.client.HTTPSConnection(hostname, 443)
    path: str = parsed_url.path
    if parsed_url.query:
        path += "?" + parsed_url.query

    req_headers: dict = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "gitlab-webhook-deleter-script",
    }
    if headers:
        req_headers.update(headers)
    encoded_body: bytes | None = None
    if body is not None:
        encoded_body = body.encode("utf-8")

    conn.request(method, path, body=encoded_body, headers=req_headers)
    resp: http.client.HTTPResponse = conn.getresponse()
    resp_text: str = resp.read().decode("utf-8")
    resp_json: dict | list | None
    try:
        resp_json = json.loads(resp_text)
    except Exception:
        resp_json = None

    return resp.status, dict(resp.getheaders()), resp_json, resp_text


def get_authenticated_user(token: str, base_url: str) -> str:
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
    api_url: str = f"{base_url}/api/v4/user"
    status: int
    resp_json: dict | list | None
    resp_text: str
    status, _, resp_json, resp_text = _make_gitlab_request("GET", api_url, token)
    if status == 200 and resp_json and isinstance(resp_json, dict):
        return resp_json["username"]
    else:
        raise Exception(f"Authentication failed: {status} {resp_text}")


def get_group_projects(token: str, base_url: str, group_path: str) -> list:
    """
    Get all projects for a GitLab group/namespace, handling pagination.

    Args:
        token: GitLab personal access token.
        base_url: Base URL of the GitLab instance.
        group_path: The group or namespace path (URL-encoded).

    Returns:
        List of project objects.

    Raises:
        Exception: If the request fails.
    """
    projects: list = []
    page: int = 1
    per_page: int = 100
    while True:
        api_url: str = (
            f"{base_url}/api/v4/groups/{group_path}/projects?include_subgroups=true&per_page={per_page}&page={page}"
        )
        status: int
        resp_json: dict | list | None
        resp_text: str
        status, _, resp_json, resp_text = _make_gitlab_request("GET", api_url, token)
        if status != 200:
            raise Exception(f"Failed to get projects for group '{group_path}': {status} {resp_text}")
        page_projects: list = resp_json if isinstance(resp_json, list) else []
        projects.extend(page_projects)
        if len(page_projects) < per_page:
            break
        page += 1
    return projects


def get_project_hooks(token: str, base_url: str, project_id: int) -> list:
    """
    Get existing webhooks for a GitLab project.

    Args:
        token: GitLab personal access token.
        base_url: Base URL of the GitLab instance.
        project_id: Numeric project ID.

    Returns:
        List of existing webhooks.

    Raises:
        Exception: If the request fails.
    """
    api_url: str = f"{base_url}/api/v4/projects/{project_id}/hooks"
    status: int
    resp_json: dict | list | None
    resp_text: str
    status, _, resp_json, resp_text = _make_gitlab_request("GET", api_url, token)
    if status == 200:
        return resp_json if isinstance(resp_json, list) else []
    else:
        raise Exception(f"Failed to get project hooks: {status} {resp_text}")


def delete_project_hook(token: str, base_url: str, project_id: int, hook_id: int) -> None:
    """
    Delete a webhook from a GitLab project.

    Args:
        token: GitLab personal access token.
        base_url: Base URL of the GitLab instance.
        project_id: Numeric project ID.
        hook_id: Numeric hook ID to delete.

    Raises:
        Exception: If deletion fails.
    """
    api_url: str = f"{base_url}/api/v4/projects/{project_id}/hooks/{hook_id}"
    status: int
    resp_text: str
    status, _, _, resp_text = _make_gitlab_request("DELETE", api_url, token)
    if status != 204:
        raise Exception(f"Failed to delete webhook: {status} {resp_text}")


def main() -> None:
    parser: argparse.ArgumentParser = argparse.ArgumentParser(
        description="Delete GitLab webhooks pointing to dev.neo.sagittal.ai."
    )
    parser.add_argument(
        "namespaces",
        nargs="+",
        help="List of GitLab group/namespace paths (e.g., 'mygroup' or 'mygroup/subgroup').",
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
    parser.add_argument("--delete", action="store_true", help="Delete the matching webhooks")
    args: argparse.Namespace = parser.parse_args()

    gitlab_token: str | None = args.token or os.environ.get("GITLAB_TOKEN")
    base_url: str = args.base_url or os.environ.get("GITLAB_BASE_URL", "https://gitlab.com")

    if not gitlab_token:
        print("Error: GitLab token not provided. Use --token or set GITLAB_TOKEN env variable.", file=sys.stderr)
        sys.exit(1)

    base_url = base_url.rstrip("/")

    try:
        user: str = get_authenticated_user(gitlab_token, base_url)
    except Exception as e:
        print(f"Error authenticating with GitLab: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Authenticated as: {user}")

    neo_url: str = "dev.neo.sagittal.ai"

    for namespace in args.namespaces:
        print(f"\nProcessing namespace: {namespace}")
        encoded_namespace: str = urllib.parse.quote(namespace, safe="")

        try:
            projects: list = get_group_projects(gitlab_token, base_url, encoded_namespace)
        except Exception as e:
            print(f"  [ERROR] Could not fetch projects for namespace '{namespace}': {e}", file=sys.stderr)
            continue

        if not projects:
            print(f"  No projects found in namespace '{namespace}'.")
            continue

        for project in projects:
            project_id: int = project["id"]
            project_path: str = project.get("path_with_namespace", str(project_id))

            try:
                hooks: list = get_project_hooks(gitlab_token, base_url, project_id)
            except Exception as e:
                print(f"  [ERROR] Could not fetch webhooks for project '{project_path}': {e}", file=sys.stderr)
                continue

            matching_hooks: list = [hook for hook in hooks if neo_url in hook.get("url", "")]

            if not matching_hooks:
                print(f"  No matching webhooks found for project '{project_path}'.")
                continue

            print(f"  Matching webhooks for project '{project_path}':")
            for hook in matching_hooks:
                print(f"    - {hook['id']}: {hook['url']}")

            if args.delete:
                for hook in matching_hooks:
                    hook_id: int = hook["id"]
                    try:
                        delete_project_hook(gitlab_token, base_url, project_id, hook_id)
                        print(f"    [OK] Deleted webhook {hook_id} from project '{project_path}'")
                    except Exception as e:
                        print(
                            f"    [ERROR] Failed to delete webhook {hook_id} from project '{project_path}': {e}",
                            file=sys.stderr,
                        )

    print("\nDone.")


if __name__ == "__main__":
    main()
