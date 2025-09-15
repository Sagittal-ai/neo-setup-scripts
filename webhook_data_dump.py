import json
import os
import sys

import click

# Set up sys.path so we can import from the project root
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from result import Err, Ok, Result
from tools.code_repositories.code_repository_config import ADORepositoryConfig, CodeRepositoryConfig
from tools.doc_management.doc_manager_config import DocManagerConfig
from tools.project_management.project_manager_config import ADOProjectManagerConfig, ProjectManagerConfig
from tools.webhook.neo_webhook import NeoWebhook

from customer_config import CustomerConfig
from customer_db import read_customer_by_uuid
from setup.setup_handler import SetupHandler, TokenCheck, WebhookConfig
from setup.setup_handler_factory import SetupHandlerFactory


@click.command()
@click.argument("customer_name")
@click.argument("customer_uuid")
@click.argument("project_id")
@click.argument("tool_kind")
@click.argument("tool")
@click.option(
    "--output",
    "-o",
    default=None,
    help="Output JSON file (default: webhooks_<customer_name>_<project_name>_<tool>.json)",
)
def main(customer_name: str, customer_uuid: str, project_id: str, tool_kind: str, tool: str, output: str):
    """
    Dump the expected webhooks for a given customer/project/tool as a JSON file.

    Arguments:
        CUSTOMER_NAME: The customer name
        CUSTOMER_UUID: The customer UUID
        PROJECT_ID: The project ID (internal project_id, not project_uuid)
        TOOL_KIND: The kind of tool (e.g. project_manager, code_repository, doc_manager)
        TOOL: The tool name (e.g. GitHub, Jira, Bitbucket, etc)
    """
    # Load customer config from DB
    customer_data = read_customer_by_uuid(customer_uuid)
    if not customer_data:
        click.echo(f"Could not find customer with uuid: {customer_uuid}", err=True)
        sys.exit(1)

    try:
        customer_config = CustomerConfig.model_validate(customer_data)
    except Exception as e:
        click.echo(f"Could not parse customer config: {e}", err=True)
        sys.exit(1)

    # Find the project config by project_id
    project_config = customer_config.projects.get(project_id)
    if not project_config:
        click.echo(f"Could not find project with id: {project_id}", err=True)
        sys.exit(1)

    # Get the factory for the tool
    factory = SetupHandlerFactory.create_setup_handler_factory(tool)
    if not factory:
        click.echo(f"Could not find SetupHandlerFactory for tool: {tool}", err=True)
        sys.exit(1)

    # Prepare webhook config
    neo_url = os.environ.get("NEO_URL", "https://dev.neo.sagittal.ai")
    access_token = customer_config.access_token

    all_webhooks: dict[str, list[NeoWebhook]] = {}
    for tool_config_kind, tool_config in project_config.iterate_configs():
        if tool_config_kind != tool_kind:
            click.echo(f"Skipping config {tool_config_kind}")
            continue

        # Create the setup handler
        result: Result[SetupHandler, TokenCheck]
        project: str
        if isinstance(tool_config, ProjectManagerConfig):
            webhook_config = WebhookConfig(
                key=tool_config.project,
                neo_url=neo_url,
                pat=access_token,
                project_id=project_id,
            )

            result = factory.create_project_management_handler(tool_config, webhook_config)
            project: str = tool_config.project

            if isinstance(tool_config, ADOProjectManagerConfig):
                project = f"{tool_config.organization_url.split('/')[-1]}/{tool_config.project}"

        elif isinstance(tool_config, CodeRepositoryConfig):
            webhook_config = WebhookConfig(
                key=tool_config.repo,
                neo_url=neo_url,
                pat=access_token,
                project_id=project_id,
            )

            result = factory.create_code_repository_handler(tool_config, webhook_config)
            project: str = tool_config.repo

            if isinstance(tool_config, ADORepositoryConfig):
                project = f"{tool_config.organization_url.split('/')[-1]}/{tool_config.repo}"

        elif isinstance(tool_config, DocManagerConfig):  # type: ignore (I want to be explicit)
            click.echo("Webhooks for Doc manager are currently not supported")
            sys.exit(1)

        else:
            click.echo(f"Unknown tool_kind: {tool_kind}", err=True)
            sys.exit(1)

        match result:
            case Ok(setup_handler):
                pass
            case Err(err):
                click.echo(f"Token check failed: {err.description}", err=True)
                sys.exit(1)

        # Get expected webhooks
        match setup_handler.get_expected_webhooks():
            case Ok(webhooks_result):
                all_webhooks[project] = webhooks_result
            case Err(err):
                click.echo(f"Could not get webhooks for {tool_config_kind}")
                sys.exit(1)

    webhooks_json = {}
    for project, webhooks in all_webhooks.items():
        webhooks_json[project] = [webhook.model_dump() for webhook in webhooks]

    # Determine output file
    if not output:
        output = f"webhooks_{customer_name}_{project_config.project_name}_{tool}.json"

    with open(output, "w", encoding="utf-8") as f:
        json.dump(webhooks_json, f, indent=2)

    click.echo(f"Dumped {len(webhooks_json)} webhooks to {output}")


if __name__ == "__main__":
    main()
