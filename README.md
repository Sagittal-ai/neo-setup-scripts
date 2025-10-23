# Neo Set Up Scripts

A collection of scripts to manage [Neo's](https://sagittal.ai/win) set up in your tools.

## Installation Instructions

To install 'uv', use the following command:

```
curl -LsSf https://astral.sh/uv/install.sh | sh
```

After installing 'uv', you can run our setup scripts like so:

```
uvx --from "git+https://github.com/Sagittal-ai/neo-setup-scripts" ado-create <datafile.json> --token <token>
```

## Running Scripts

After installing 'uv', you can run the available scripts using the following commands:

### ADO Create Webhook:
```
uvx --from "git+https://github.com/Sagittal-ai/neo-setup-scripts" ado-create <datafile.json> --token <token>
```

### ADO Delete Webhook:

Run script without delete flag to sanity check deletion plan:
```
uvx --from "git+https://github.com/Sagittal-ai/neo-setup-scripts" ado-delete <organization> --token <token>
```

Then run with deletion flag to execute deletions:
```
uvx --from "git+https://github.com/Sagittal-ai/neo-setup-scripts" ado-delete <organization> --token <token> --delete
```

### Bitbucket Create Webhook:

```
uvx --from "git+https://github.com/Sagittal-ai/neo-setup-scripts" bitbucket-create <datafile.json> --token <token>
```

### Bitbucket Delete Webhook:

Run script without delete flag to sanity check deletion plan:
```
uvx --from "git+https://github.com/Sagittal-ai/neo-setup-scripts" bitbucket-delete <workspace> --token <token>
```

Then run with deletion flag to execute deletions:
```
uvx --from "git+https://github.com/Sagittal-ai/neo-setup-scripts" bitbucket-delete <workspace> --token <token> --delete
```

### GitHub Create Webhook:

```
uvx --from "git+https://github.com/Sagittal-ai/neo-setup-scripts" github-create <datafile.json> --token <token>
```

### GitHub Delete Webhook:

Run script without delete flag to sanity check deletion plan:
```
uvx --from "git+https://github.com/Sagittal-ai/neo-setup-scripts" github-delete <repositories> --token <token> --delete
```

Then run with deletion flag to execute deletions:
```
uvx --from "git+https://github.com/Sagittal-ai/neo-setup-scripts" github-delete <repositories> --token <token>
```

*Note: the `repositories` argument accepts multiple repositories e.g. `--repositories octocat/Hello-World microsoft/vscode`*

### GitLab Create Webhook:

```
uvx --from "git+https://github.com/Sagittal-ai/neo-setup-scripts" gitlab-create <config_file> --token <token> --base-url <base_url>
```

### Jira Create Webhook:

```
uvx --from "git+https://github.com/Sagittal-ai/neo-setup-scripts" jira-create <config_file> --username <username> --token <token> --base-url <base-url>
```

### Notes

- The datafiles can be downloaded from our project management pages on our website.
