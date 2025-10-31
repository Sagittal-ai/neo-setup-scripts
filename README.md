# Neo Set Up Scripts

A collection of scripts to manage [Neo's](https://sagittal.ai/win) set up in your tools.

These scripts have all been implemented only using Python standard libraries and have no third party dependencies. Whilst we recomend you use `uv` to run the scripts for ease of use, it's not striclty necessary!

## Installation Instructions

To install `uv`, use the following command:

```
curl -LsSf https://astral.sh/uv/install.sh | sh
```

After installing `uv`, you can run our setup scripts like so:

```
uvx --from "git+https://github.com/Sagittal-ai/neo-setup-scripts" ado-create <datafile.json> --token <token>
```

## Running Scripts

### Create Webhooks

The webhook creation scripts require datafiles that can be downloaded from the project management pages on our website. The webhook creation scripts will create all webhooks in the datafile that are not already present in your tool.

#### ADO

```
uvx --from "git+https://github.com/Sagittal-ai/neo-setup-scripts" ado-create <datafile.json> --token <token>
```

#### BitBucket

```
uvx --from "git+https://github.com/Sagittal-ai/neo-setup-scripts" bitbucket-create <datafile.json> --token <token>
```

#### GitHub
```
uvx --from "git+https://github.com/Sagittal-ai/neo-setup-scripts" github-create <datafile.json> --token <token>
```
#### GitLab

```
uvx --from "git+https://github.com/Sagittal-ai/neo-setup-scripts" gitlab-create <config_file> --token <token> --base-url <base_url>
```

#### Jira

```
uvx --from "git+https://github.com/Sagittal-ai/neo-setup-scripts" jira-create <config_file> --username <username> --token <token> --base-url <base-url>
```

### Delete Webhooks

The webhook deletion scripts will scan all available webhooks visible to your token, will match any pointed to our domains and will delete them. You must use the `--delete` flag to perform the deletions, otherwise the script will just output informational statements.

#### ADO

```
uvx --from "git+https://github.com/Sagittal-ai/neo-setup-scripts" ado-delete <organization> --token <token>
uvx --from "git+https://github.com/Sagittal-ai/neo-setup-scripts" ado-delete <organization> --token <token> --delete
```

#### Bitbucket

```
uvx --from "git+https://github.com/Sagittal-ai/neo-setup-scripts" bitbucket-delete <workspace> --token <token>
uvx --from "git+https://github.com/Sagittal-ai/neo-setup-scripts" bitbucket-delete <workspace> --token <token> --delete
```

#### GitHub

```
uvx --from "git+https://github.com/Sagittal-ai/neo-setup-scripts" github-delete <repositories> --token <token>
uvx --from "git+https://github.com/Sagittal-ai/neo-setup-scripts" github-delete <repositories> --token <token> --delete
```

*Note: the `repositories` argument accepts multiple repositories e.g. `--repositories octocat/Hello-World microsoft/vscode`*