import argparse
import http.client
import json
import os
import sys
import urllib.parse


def _make_github_request(method, url, token, headers=None, body=None):
    headers = headers or {}
    headers["Authorization"] = f"token {token}"
    headers["User-Agent"] = "Python Script"
    headers["Accept"] = "application/vnd.github.v3+json"

    parsed_url = urllib.parse.urlparse(url)
    conn = http.client.HTTPSConnection(parsed_url.netloc)
    conn.request(method, parsed_url.path, body, headers)
    resp = conn.getresponse()
    resp_text = resp.read().decode()
    try:
        resp_json = json.loads(resp_text)
    except json.JSONDecodeError:
        resp_json = None

    return resp.status, dict(resp.getheaders()), resp_json, resp_text


def get_repo_hooks(token, repo_full_name):
    url = f"https://api.github.com/repos/{repo_full_name}/hooks"
    status, headers, hooks, _ = _make_github_request("GET", url, token)
    if status != 200:
        raise Exception(f"Failed to get hooks for {repo_full_name}: {status}")
    return hooks


def delete_repo_hook(token, repo_full_name, hook_id):
    url = f"https://api.github.com/repos/{repo_full_name}/hooks/{hook_id}"
    status, headers, _, _ = _make_github_request("DELETE", url, token)
    if status != 204:
        raise Exception(f"Failed to delete hook {hook_id} for {repo_full_name}: {status}")


def main():
    parser = argparse.ArgumentParser(description="Delete GitHub webhooks pointing to dev.neo.sagittal.ai.")
    parser.add_argument(
        "repositories",
        nargs="+",
        help="List of GitHub repositories in the format 'owner/repo'.",
    )
    parser.add_argument(
        "--token",
        "-t",
        type=str,
        default=None,
        help="GitHub personal access token. If not provided, will use GITHUB_TOKEN environment variable.",
    )
    parser.add_argument(
        "--delete",
        action="store_true",
        help="Actually delete the webhooks. If not set, the script will only print what it would do.",
    )
    args = parser.parse_args()

    github_token = args.token or os.environ.get("GITHUB_TOKEN")
    if not github_token:
        print("Error: GitHub token not provided. Use --token or set GITHUB_TOKEN env variable.", file=sys.stderr)
        sys.exit(1)

    target_substring = "dev.neo.sagittal.ai"

    for repo_full_name in args.repositories:
        print(f"\nProcessing repository: {repo_full_name}")
        try:
            hooks = get_repo_hooks(github_token, repo_full_name)
        except Exception as e:
            print(f"  [ERROR] Could not fetch existing webhooks: {e}", file=sys.stderr)
            continue

        if hooks is None:
            print(f"  [ERROR] No hooks found for {repo_full_name}.", file=sys.stderr)
            continue

        for hook in hooks:
            hook_id = hook.get("id")
            hook_url = hook.get("config", {}).get("url")
            if target_substring in hook_url:
                print(f"  [FOUND] Webhook pointing to '{target_substring}' with ID {hook_id}.")
                if args.delete:
                    try:
                        delete_repo_hook(github_token, repo_full_name, hook_id)
                        print(f"  [DELETED] Webhook with ID {hook_id}.")
                    except Exception as e:
                        print(f"  [ERROR] Failed to delete webhook with ID {hook_id}: {e}", file=sys.stderr)
                else:
                    print(f"  [SKIP] --delete flag not set. Webhook with ID {hook_id} not deleted.")

    print("\nDone.")


if __name__ == "__main__":
    main()
