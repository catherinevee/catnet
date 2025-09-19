"""
GitOps commands for CatNet CLI
"""
import click
import asyncio
import sys
import secrets
from typing import Optional

from catnet_cli.client import CatNetAPIClient, AuthenticationError
from catnet_cli.utils import (
    print_success, print_error, print_info,
    handle_error, format_table
)


@click.group()
def gitops():
    """GitOps repository management commands"""
    pass


@gitops.command('connect')
@click.option('--url', '-u', required=True, help='Git repository URL')
@click.option('--branch', '-b', default='main', help='Git branch (default: main)')
@click.option('--webhook-secret', help='Secret for webhook verification (auto-generated if not provided)')
@click.option('--path', default='/', help='Path within repository containing configs')
@click.pass_context
def connect_repository(
    ctx: click.Context,
    url: str,
    branch: str,
    webhook_secret: Optional[str],
    path: str
):
    """Connect a Git repository for configuration management

    Examples:
        catnet gitops connect --url https://github.com/org/network-configs
        catnet gitops connect -u git@github.com:org/configs.git --branch main
        catnet gitops connect -u https://gitlab.com/org/configs --webhook-secret abc123
    """
    config = ctx.obj.get('config', {})
    debug = ctx.obj.get('debug', False)

    # Generate webhook secret if not provided
    if not webhook_secret:
        webhook_secret = secrets.token_urlsafe(32)
        print_info(f"Generated webhook secret: {webhook_secret}")
        print_info("Save this secret for configuring the webhook in your Git provider")

    async def connect():
        async with CatNetAPIClient(config) as client:
            try:
                result = await client.connect_repository(
                    url=url,
                    branch=branch,
                    webhook_secret=webhook_secret
                )

                repo_id = result.get('id')
                webhook_url = result.get('webhook_url')

                print_success(f"Repository connected successfully")
                print_info(f"Repository ID: {repo_id}")
                print_info(f"Branch: {branch}")

                if webhook_url:
                    click.echo("\n=== Webhook Configuration ===")
                    click.echo(f"Webhook URL: {webhook_url}")
                    click.echo(f"Webhook Secret: {webhook_secret}")
                    click.echo("\nConfigure these in your Git provider:")
                    click.echo("- GitHub: Settings → Webhooks → Add webhook")
                    click.echo("- GitLab: Settings → Webhooks")
                    click.echo("- Bitbucket: Settings → Webhooks → Add webhook")

                return result

            except AuthenticationError:
                print_error("Authentication required. Please login first.")
                sys.exit(2)
            except Exception as e:
                handle_error(e, debug)
                sys.exit(1)

    loop = asyncio.get_event_loop()
    loop.run_until_complete(connect())


@gitops.command('sync')
@click.option('--repo-id', '-r', required=True, help='Repository ID')
@click.option('--force/--no-force', default=False, help='Force sync even with conflicts')
@click.pass_context
def sync_repository(ctx: click.Context, repo_id: str, force: bool):
    """Synchronize configurations from Git repository

    This will:
    - Pull latest changes from repository
    - Validate all configurations
    - Check for secrets and sensitive data
    - Create deployments if auto-deploy is enabled

    Examples:
        catnet gitops sync --repo-id abc-123-def
        catnet gitops sync -r repo-prod-001 --force
    """
    config = ctx.obj.get('config', {})
    debug = ctx.obj.get('debug', False)

    async def sync():
        async with CatNetAPIClient(config) as client:
            try:
                print_info(f"Synchronizing repository {repo_id}...")

                result = await client.sync_repository(repo_id, force=force)

                status = result.get('status')
                files_synced = result.get('files_synced', [])
                validation_results = result.get('validation', {})
                deployments_created = result.get('deployments_created', [])

                print_success(f"Repository synchronized successfully")
                print_info(f"Status: {status}")
                print_info(f"Files synced: {len(files_synced)}")

                # Show validation results
                if validation_results:
                    click.echo("\n=== Validation Results ===")
                    valid_count = validation_results.get('valid', 0)
                    invalid_count = validation_results.get('invalid', 0)
                    warning_count = validation_results.get('warnings', 0)

                    print_success(f"✓ Valid configurations: {valid_count}")
                    if invalid_count > 0:
                        print_error(f"✗ Invalid configurations: {invalid_count}")
                    if warning_count > 0:
                        print_info(f"⚠ Warnings: {warning_count}")

                # Show created deployments
                if deployments_created:
                    click.echo("\n=== Deployments Created ===")
                    for dep_id in deployments_created:
                        print_info(f"  - {dep_id}")

                return result

            except AuthenticationError:
                print_error("Authentication required. Please login first.")
                sys.exit(2)
            except Exception as e:
                handle_error(e, debug)
                sys.exit(1)

    loop = asyncio.get_event_loop()
    loop.run_until_complete(sync())


@gitops.command('list')
@click.pass_context
def list_repositories(ctx: click.Context):
    """List all connected Git repositories

    Examples:
        catnet gitops list
    """
    config = ctx.obj.get('config', {})
    debug = ctx.obj.get('debug', False)

    async def list_repos():
        async with CatNetAPIClient(config) as client:
            try:
                repositories = await client.list_repositories()

                if not repositories:
                    print_info("No repositories connected")
                    return

                headers = ['ID', 'URL', 'Branch', 'Status', 'Last Sync']
                rows = []
                for repo in repositories:
                    rows.append([
                        repo.get('id', '')[:12],
                        repo.get('url', ''),
                        repo.get('branch', ''),
                        repo.get('status', ''),
                        repo.get('last_sync', 'Never')
                    ])

                click.echo(format_table(headers, rows))
                click.echo(f"\nTotal repositories: {len(repositories)}")

                return repositories

            except AuthenticationError:
                print_error("Authentication required. Please login first.")
                sys.exit(2)
            except Exception as e:
                handle_error(e, debug)
                sys.exit(1)

    loop = asyncio.get_event_loop()
    loop.run_until_complete(list_repos())


@gitops.command('disconnect')
@click.argument('repo_id')
@click.option('--force', is_flag=True, help='Skip confirmation')
@click.pass_context
def disconnect_repository(ctx: click.Context, repo_id: str, force: bool):
    """Disconnect a Git repository

    Examples:
        catnet gitops disconnect repo-123
        catnet gitops disconnect repo-456 --force
    """
    config = ctx.obj.get('config', {})
    debug = ctx.obj.get('debug', False)

    if not force:
        from catnet_cli.utils import confirm_action
        if not confirm_action(f"Disconnect repository '{repo_id}'?"):
            print_info("Disconnect cancelled")
            return

    async def disconnect():
        async with CatNetAPIClient(config) as client:
            try:
                result = await client.request(
                    'DELETE',
                    f'/gitops/{repo_id}',
                    service='gitops'
                )

                print_success(f"Repository '{repo_id}' disconnected successfully")
                return result

            except AuthenticationError:
                print_error("Authentication required. Please login first.")
                sys.exit(2)
            except Exception as e:
                handle_error(e, debug)
                sys.exit(1)

    loop = asyncio.get_event_loop()
    loop.run_until_complete(disconnect())