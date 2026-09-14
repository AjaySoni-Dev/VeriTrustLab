# Main branch protection

Apply a GitHub repository ruleset to the `main` branch after this folder is connected to its GitHub repository.

Required settings:

- require changes through a pull request;
- require at least one approving review;
- dismiss stale approvals when new commits are pushed;
- require all review conversations to be resolved;
- require the `Release gate` status check;
- require the branch to be up to date before merging;
- block force pushes and branch deletion;
- apply the ruleset to repository administrators as well as contributors.

The required status-check name comes from `.github/workflows/ci.yml`. If the workflow job name changes, update the repository ruleset to match it.
