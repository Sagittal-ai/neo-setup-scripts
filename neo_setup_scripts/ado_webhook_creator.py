#!/usr/bin/env python3

import argparse
import base64
import http.client
import json
import os
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


def get_repo_hooks(token, project, repo):
    """
    Retrieve existing webhooks for a given Azure DevOps repository.

    Args:
        token: Azure DevOps personal access token.
        project: Project name.
        repo: Repository name.

    Returns:
        List of existing webhooks.

    Raises:
        Exception: If fetching webhooks fails.
    """
    api_url = f"https://dev.azure.com/{project}/_apis/hooks/subscriptions?api-version=7.1-preview.1"
    status, headers, resp_json, resp_text = _make_ado_request("GET", api_url, token)
    if status == 200:
        return (resp_json or {}).get("value", [])
    else:
        raise Exception(f"Failed to fetch webhooks: {status} {resp_text}")


def snake_to_camel(snake_str):
    parts = snake_str.split("_")
    return parts[0] + "".join(word.capitalize() for word in parts[1:])


def create_hook(token, organization, url, event_type, project_id, publisher_inputs, repository_id=None):
    """
    Create a webhook for a repository in Azure DevOps.

    Args:
        token: Azure DevOps personal access token.
        project: Project name.
        repo: Repository name.
        url: Webhook URL.
        event_type: Event name to subscribe to.
        description: Description of the webhook.
        active: Whether the webhook should be active.

    Returns:
        The created webhook object.

    Raises:
        Exception: If webhook creation fails.
    """
    # https://dev.azure.com/Sagittal/_apis/hooks/subscriptions

    api_url = f"https://dev.azure.com/{organization}/_apis/hooks/subscriptions?api-version=7.1-preview.1"
    publisher_inputs_camel = {}
    for key, value in publisher_inputs.items():
        key_camel = snake_to_camel(key)
        publisher_inputs_camel[key_camel] = value

    publisher_inputs_camel["projectId"] = project_id
    del publisher_inputs_camel["projectName"]

    if publisher_inputs_camel.get("repositoryName") and event_type != "build.complete":
        publisher_inputs_camel["repository"] = repository_id
        del publisher_inputs_camel["repositoryName"]

    version: str = "1.0"
    match event_type:
        case "workitem.updated":
            pass
        case "workitem.commented":
            pass
        case "workitem.created":
            pass
        case "ms.vss-code.git-pullrequest-comment-event":
            version = "2.0"
        case "git.pullrequest.updated":
            pass
        case "git.pullrequest.created":
            pass
        case "build.complete":
            version = "2.0"
        case _:
            raise Exception("Unexpected webhook, contact Sagittal Support for assistance!")

    data = {
        "publisherId": "tfs",
        "consumerId": "webHooks",
        "consumerActionId": "httpRequest",
        "eventType": event_type,
        "consumerInputs": {
            "url": url,
        },
        "publisherInputs": publisher_inputs_camel,
        "resourceVersion": version,
        "scope": 1,
    }
    body = json.dumps(data, indent=2)
    status, headers, resp_json, resp_text = _make_ado_request("POST", api_url, token, body=body)
    if status in (201, 200) and resp_json:
        return resp_json
    else:
        raise Exception(f"Failed to create webhook: {status} {resp_text}")


def get_project_id(token, organization, project_name) -> str:
    api_url = f"https://dev.azure.com/{organization}/_apis/projects?api-version=7.1-preview.1"
    status, headers, resp_json, resp_text = _make_ado_request("GET", api_url, token)
    if status in (201, 200) and resp_json:

        data = resp_json.get("value", [])
        projects = [project.get("name") for project in data]
        print(f"  [INFO] This token can see the projects: {', '.join(projects)}")

        for project in data:
            if project_name == project.get("name"):
                return project.get("id")

        raise Exception(f"Failed to find project id for {project_name}")

    else:
        raise Exception(f"Failed to find project_id: {status} {resp_text}")


def get_repository_id(token, organization, project_name, respository_name) -> str:
    api_url = f"https://dev.azure.com/{organization}/{project_name}/_apis/git/repositories?api-version=7.1"
    status, headers, resp_json, resp_text = _make_ado_request("GET", api_url, token)
    if status in (201, 200) and resp_json:
        data = resp_json.get("value", [])

        repositories = [repository.get("name") for repository in data]
        print(f"  [INFO] For project {project_name} token can see the repositories: {', '.join(repositories)}")

        for repository in data:
            if respository_name == repository.get("name", {}):
                return repository.get("id")

        raise Exception(f"Failed to find repository id for {respository_name}")

    else:
        raise Exception(f"Failed to find repository_id: {status} {resp_text}")


def main():
    """
    Create Azure DevOps webhooks for repositories as specified in a JSON config file.

    This script helps you automatically create webhooks on one or more Azure DevOps repositories
    using a configuration file. It is designed to be easy to use, even if you are new to Python.

    Prerequisites:
    - You need an Azure DevOps personal access token (PAT) with appropriate permissions.
    - You need a JSON configuration file describing which webhooks to create for which repositories.

    How to use:

    1. Ensure the webhooks.json file you've been given is in the same directory as the script.

    2. Run the script from the command line:

       python scripts/ado_webhook_creator.py webhooks.json --token YOUR_ADO_TOKEN

       - Replace "webhooks.json" with the path to your config file.
       - Replace "YOUR_ADO_TOKEN" with your personal access token.

       Alternatively, you can set your token as an environment variable:

       export ADO_TOKEN=YOUR_ADO_TOKEN
       python scripts/ado_webhook_creator.py webhooks.json

    3. The script will:
       - Authenticate with Azure DevOps.
       - For each repository in your config, check if the webhook already exists (by URL).
       - Create any missing webhooks as specified.

    Notes:
    - You do NOT need to install any extra Python packages; this script uses only the standard library.
    - If you see errors about authentication or permissions, check your token and repository access.
    - You must have admin rights on the repository to add webhooks.
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
        help="Azure DevOps personal access token. If not provided, will use ADO_TOKEN environment variable.",
    )
    args = parser.parse_args()

    config_file = args.config_file
    ado_token = args.token or os.environ.get("ADO_TOKEN")
    if not ado_token:
        print("Error: Azure DevOps token not provided. Use --token or set ADO_TOKEN env variable.", file=sys.stderr)
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
        try:
            organization, repo = repo_full_name.split("/")
        except ValueError as e:
            print(f"  [ERROR] {e}", file=sys.stderr)
            continue

        # Get existing webhooks to avoid duplicates
        try:
            existing_hooks = get_repo_hooks(ado_token, organization, repo)
        except Exception as e:
            print(f"  [ERROR] Could not fetch existing webhooks: {e}", file=sys.stderr)
            continue

        for webhook in webhooks:
            url = webhook.get("url")
            config_obj = webhook.get("config", {})
            event_type = config_obj.get("event_type", [])
            name = webhook.get("info", {}).get("name", "ADO Webhook")
            publisher_inputs = config_obj.get("publisher_inputs", {})
            project_name = publisher_inputs.get("project_name")
            repository_name = publisher_inputs.get("repository_name")
            area_path = publisher_inputs.get("area_path")

            project_id = get_project_id(ado_token, organization, project_name)
            repository_id = None

            if repository_name:
                repository_id = get_repository_id(ado_token, organization, project_name, repository_name)

            # Check if webhook with same URL already exists
            already_exists = False
            for hook in existing_hooks:
                if hook.get("consumerInputs", {}).get("url") == url:
                    existing_publisher_inputs = hook.get("publisherInputs")
                    existing_area_path = existing_publisher_inputs.get("areaPath")
                    existing_repository_id = existing_publisher_inputs.get("repository")
                    current_event_type = hook.get("eventType")

                    # Build
                    if not existing_area_path and not existing_repository_id:
                        if url == hook.get("consumerInputs", {}).get("url") and event_type == current_event_type:
                            already_exists = True
                            break

                    # Repository Webhooks
                    if repository_id and existing_repository_id and repository_id == existing_repository_id:
                        if url == hook.get("consumerInputs", {}).get("url") and event_type == current_event_type:
                            already_exists = True
                            break

                    # Project webhooks
                    if project_name and existing_area_path and project_name in existing_area_path:
                        if url == hook.get("consumerInputs", {}).get("url") and event_type == current_event_type:
                            already_exists = True
                            break

            if already_exists:
                print(f"  [SKIP] Webhook {name} for URL '{url}' already exists.")
                continue

            # Attempt to create webhook
            try:
                create_hook(
                    ado_token,
                    organization,
                    url,
                    event_type,
                    project_id,
                    publisher_inputs,
                    repository_id=repository_id,
                )
                print(f"  [OK] Created webhook '{name}' for event {event_type}")
            except Exception as e:
                print(f"  [ERROR] Failed to create webhook '{name}': {e}", file=sys.stderr)

    print("\nDone.")


if __name__ == "__main__":
    main()
