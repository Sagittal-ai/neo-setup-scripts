import argparse
import base64
import http.client
import json
import sys
import urllib.parse


def _make_ado_request(method, url, token, headers=None, body=None):
    """
    Make an Azure DevOps API request using only the standard library.

    Args:
        method: HTTP method (e.g., "GET", "POST").
        url: Full URL to request.
        token: Azure DevOps personal access token.
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
        "Authorization": f"Basic {base64.b64encode(f':{token}'.encode()).decode().strip()}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "ado-webhook-creator-script",
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


def get_repo_hooks(token, organization):
    """
    Retrieve existing webhooks for ADO

    Args:
        token: Azure DevOps personal access token.

    Returns:
        List of existing webhooks.

    Raises:
        Exception: If fetching webhooks fails.
    """
    api_url = f"https://dev.azure.com/{organization}/_apis/hooks/subscriptions?api-version=7.1-preview.1"
    status, headers, resp_json, resp_text = _make_ado_request("GET", api_url, token)
    if status == 200:
        return (resp_json or {}).get("value", [])
    else:
        raise Exception(f"Failed to fetch webhooks: {status} {resp_text}")


def delete_hook(token, organization, hook_id):
    url = f"https://dev.azure.com/{organization}/_apis/hooks/subscriptions/{hook_id}?api-version=6.0"
    status, headers, resp_json, resp_text = _make_ado_request("DELETE", url, token)
    if status != 204:
        raise Exception(f"Failed to delete webhook: {resp_text}")


def main():
    parser = argparse.ArgumentParser(description="Manage ADO webhooks.")
    parser.add_argument("organization", help="The Azure DevOps organization name.")
    parser.add_argument(
        "--token",
        "-t",
        type=str,
        default=None,
        help="Azure DevOps personal access token. If not provided, will use ADO_TOKEN environment variable.",
    )
    parser.add_argument("--delete", action="store_true", help="Delete the matching webhooks")
    args = parser.parse_args()

    try:
        hooks = get_repo_hooks(args.token, args.organization)
    except Exception as e:
        print(f"[ERROR] Could not fetch webhooks: {e}", file=sys.stderr)
        sys.exit(1)

    neo_url = "https://dev.neo.sagittal.ai"
    matching_hooks = [hook for hook in hooks if neo_url in hook.get("consumerInputs", {}).get("url", "")]

    if not matching_hooks:
        print("No matching webhooks found.")
        return

    print("Matching webhooks:")
    for hook in matching_hooks:
        print(f"  - {hook['id']}: {hook['consumerInputs']['url']}")

    if args.delete:
        print("\n\n")
        for hook in matching_hooks:
            try:
                delete_hook(args.token, args.organization, hook["id"])
                print(f"  [OK] Deleted webhook {hook['id']}")
            except Exception as e:
                print(f"  [ERROR] Failed to delete webhook {hook['id']}: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()