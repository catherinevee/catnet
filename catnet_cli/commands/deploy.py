"""
Deployment commands for CatNet CLI
"""
import click
import asyncio
import sys
from typing import Optional, List
from pathlib import Path
import json
import yaml

from catnet_cli.client import (
    CatNetAPIClient,
    AuthenticationError,
    NotFoundError,
)
from catnet_cli.utils import (
    print_success, print_error, print_info, print_warning,
    handle_error, format_table, confirm_action, format_timestamp
)


@click.group()

def deploy():
    """Deployment management commands"""
    pass


@deploy.command('create')
@click.option(
    '--config-file',
    '-f',
    required=True,
    type=click.Path(exists=True),
    help='Configuration file path'
)
@click.option(
    '--target',
    '-t',
    multiple=True,
    required=True,
    help='Target devices (can specify multiple)'
)
@click.option(
    '--strategy',
    type=click.Choice(['rolling',
    'canary',
    'blue-green']),
    default='rolling',
    help='Deployment strategy'
)
@click.option(
    '--dry-run/--no-dry-run',
    default=False,
    help='Perform validation without actual deployment'
)
@click.option(
    '--approval-required/--no-approval',
    default=True,
    help='Require approval before execution'
)
@click.pass_context
def create_deployment(
    ctx: click.Context,
    config_file: str,
    target: tuple,
    strategy: str,
    dry_run: bool,
    approval_required: bool
):
    """Create a new configuration deployment

    Examples:
        catnet deploy create --config-file configs/router.yml --target device1 \
            --target device2
        catnet deploy create -f config.json -t router1 --strategy canary \
            --dry-run
        catnet deploy create -f update.yaml -t switch1 -t switch2 --no-approval
    """
    config = ctx.obj.get('config', {})
    debug = ctx.obj.get('debug', False)

    if not target:
        print_error("At least one target device is required")
        sys.exit(1)

    # Show deployment plan
    click.echo("\n=== Deployment Plan ===")
    click.echo(f"Configuration: {config_file}")
    click.echo(f"Target Devices: {', '.join(target)}")
    click.echo(f"Strategy: {strategy}")
    click.echo(f"Dry Run: {'Yes' if dry_run else 'No'}")
    click.echo(f"Approval Required: {'Yes' if approval_required else 'No'}")
    click.echo("")

    if not dry_run and not confirm_action("Proceed with deployment?"):
        print_info("Deployment cancelled")
        return

    async def create():
        async with CatNetAPIClient(config) as client:
            try:
                result = await client.create_deployment(
                    config_file=config_file,
                    targets=list(target),
                    strategy=strategy,
                    dry_run=dry_run
                )

                deployment_id = result.get('id')
                status = result.get('status')
                validation_results = result.get('validation', {})

                if dry_run:
                    print_success("Dry run completed successfully")
                    click.echo("\n=== Validation Results ===")
                    if validation_results.get('syntax_valid'):
                        print_success("✓ Syntax validation passed")
                    else:
                        print_error("✗ Syntax validation failed")

                    if validation_results.get('security_scan'):
                        print_success("✓ Security scan passed")
                    else:
                        print_warning("⚠ Security warnings found")

                    if 'warnings' in validation_results:
                        click.echo("\nWarnings:")
                        for warning in validation_results['warnings']:
                            print_warning(f"  - {warning}")
                else:
                    print_success(f"Deployment created successfully")
                    print_info(f"Deployment ID: {deployment_id}")
                    print_info(f"Status: {status}")

                    if approval_required:
                        print_info("\nDeployment requires approval before \
                            execution")
                        print_info(f"To approve: catnet deploy approve \
                            {deployment_id}")
                    else:
                        print_info("\nDeployment will begin automatically")

                return result

            except AuthenticationError:
                print_error("Authentication required. Please login first.")
                sys.exit(2)
            except FileNotFoundError as e:
                print_error(str(e))
                sys.exit(1)
            except Exception as e:
                handle_error(e, debug)
                sys.exit(1)

    loop = asyncio.get_event_loop()
    loop.run_until_complete(create())


@deploy.command('status')
@click.argument('deployment_id')
@click.option('--watch', '-w', is_flag=True, help='Watch deployment progress')
@click.option('--interval', default=5, help='Watch interval in seconds')
@click.pass_context

def deployment_status(
    ctx: click.Context,
    deployment_id: str,
    watch: bool,
    interval: int
):
    """Get status of a deployment

    Examples:
        catnet deploy status dep-abc-123
        catnet deploy status dep-123 --watch
        catnet deploy status dep-456 -w --interval 10
    """
    config = ctx.obj.get('config', {})
    debug = ctx.obj.get('debug', False)

    async def get_status():
        async with CatNetAPIClient(config) as client:
            try:
                while True:
                    result = await client.get_deployment_status(deployment_id)

                    # Clear screen if watching
                    if watch:
                        click.clear()

                    # Display status
                    click.echo(f"\n=== Deployment Status: {deployment_id} ===")
                    click.echo(f"Status: {result.get('status', 'Unknown')}")
                                        click.echo(
                        f"Strategy: {result.get('strategy',
                        'Unknown')}"
                    )
                    click.echo(f"Progress: {result.get('progress', 0)}%")
                                        click.echo(
                        f"Started: {format_timestamp(result.get('started_at',
                        ''))}"
                    )

                    if result.get('completed_at'):
                        click.echo(f"Completed: \
                            {format_timestamp(result['completed_at'])}")

                    # Device status
                    devices = result.get('devices', [])
                    if devices:
                        click.echo("\n=== Device Status ===")
                        headers = ['Device', 'Status', 'Progress', 'Message']
                        rows = []
                        for dev in devices:
                            rows.append([
                                dev.get('hostname', dev.get('id', '')),
                                dev.get('status', ''),
                                f"{dev.get('progress', 0)}%",
                                dev.get('message', '')[:40]  # Truncate message
                            ])
                        click.echo(format_table(headers, rows))

                    # Errors
                    if 'errors' in result and result['errors']:
                        click.echo("\n=== Errors ===")
                        for error in result['errors']:
                            print_error(f"  - {error}")

                    # Check if complete
                    final_states = ['completed', 'failed', 'rolled_back']
                    if result.get('status') in final_states:
                        if watch:
                            click.echo("\nDeployment finished.")
                        break

                    if not watch:
                        break

                    # Wait before next check
                    await asyncio.sleep(interval)

                return result

            except NotFoundError:
                print_error(f"Deployment '{deployment_id}' not found")
                sys.exit(1)
            except AuthenticationError:
                print_error("Authentication required. Please login first.")
                sys.exit(2)
            except Exception as e:
                handle_error(e, debug)
                sys.exit(1)

    loop = asyncio.get_event_loop()
    loop.run_until_complete(get_status())


@deploy.command('approve')
@click.argument('deployment_id')
@click.option('--comment', '-c', help='Approval comment for audit trail')
@click.pass_context

def approve_deployment(
    ctx: click.Context,
    deployment_id: str,
    comment: Optional[str]
):
    """Approve a pending deployment requiring authorization

    Examples:
        catnet deploy approve dep-123
        catnet deploy approve dep-123 --comment "Approved after review"
        catnet deploy approve dep-456 -c "Emergency change approved"
    """
    config = ctx.obj.get('config', {})
    debug = ctx.obj.get('debug', False)

    if not comment:
                comment = click.prompt(
            'Approval comment (optional)',
            default='',
            show_default=False
        )

    async def approve():
        async with CatNetAPIClient(config) as client:
            try:
                # Get deployment details first
                deployment = await client.get_deployment_status(deployment_id)

                click.echo(f"\n=== Deployment Details ===")
                click.echo(f"ID: {deployment_id}")
                click.echo(f"Strategy: {deployment.get('strategy')}")
                                click.echo(
                    f"Targets: {',
                    '.join(deployment.get('targets',
                    []))}"
                )
                click.echo("")

                if not confirm_action("Approve this deployment?"):
                    print_info("Approval cancelled")
                    return

                                result = await client.approve_deployment(
                    deployment_id,
                    comment
                )
                print_success(f"Deployment approved successfully")

                if comment:
                    print_info(f"Comment: {comment}")

                print_info("\nDeployment will now proceed")
                print_info(f"Monitor progress: catnet deploy status \
                    {deployment_id} --watch")

                return result

            except NotFoundError:
                print_error(f"Deployment '{deployment_id}' not found")
                sys.exit(1)
            except AuthenticationError:
                print_error("Authentication required. Please login first.")
                sys.exit(2)
            except Exception as e:
                handle_error(e, debug)
                sys.exit(1)

    loop = asyncio.get_event_loop()
    loop.run_until_complete(approve())


@deploy.command('rollback')
@click.argument('deployment_id')
@click.option(
    '--reason',
    '-r',
    required=True,
    help='Rollback reason (required for audit)'
)
@click.option(
    '--force',
    is_flag=True,
    help='Force rollback without confirmation'
)
@click.pass_context

def rollback_deployment(
    ctx: click.Context,
    deployment_id: str,
    reason: str,
    force: bool
):
    """Rollback a deployment to previous configuration

    This will:
    - Stop ongoing deployment (if in progress)
    - Restore previous configuration from backup
    - Log rollback reason for audit

    Examples:
        catnet deploy rollback dep-456 --reason "Performance degradation \
            detected"
        catnet deploy rollback dep-123 -r "Configuration error" --force
    """
    config = ctx.obj.get('config', {})
    debug = ctx.obj.get('debug', False)

    if not force:
        print_warning("WARNING: This will rollback the deployment to the \
            previous configuration")
        if not confirm_action(f"Rollback deployment '{deployment_id}'?"):
            print_info("Rollback cancelled")
            return

    async def rollback():
        async with CatNetAPIClient(config) as client:
            try:
                print_info(f"Initiating rollback for deployment \
                    {deployment_id}...")

                                result = await client.rollback_deployment(
                    deployment_id,
                    reason
                )

                print_success("Rollback initiated successfully")
                print_info(f"Reason: {reason}")

                # Show rollback status
                rollback_id = result.get('rollback_id')
                if rollback_id:
                    print_info(f"Rollback ID: {rollback_id}")

                devices_rolled_back = result.get('devices_rolled_back', [])
                if devices_rolled_back:
                    click.echo("\n=== Devices Rolled Back ===")
                    for device in devices_rolled_back:
                        print_success(f"  ✓ {device}")

                print_info("\nRollback completed")
                print_info("All affected devices have been restored to \
                    previous configuration")

                return result

            except NotFoundError:
                print_error(f"Deployment '{deployment_id}' not found")
                sys.exit(1)
            except AuthenticationError:
                print_error("Authentication required. Please login first.")
                sys.exit(2)
            except Exception as e:
                handle_error(e, debug)
                sys.exit(1)

    loop = asyncio.get_event_loop()
    loop.run_until_complete(rollback())


@deploy.command('history')
@click.option(
    '--limit',
    '-l',
    default=10,
    help='Number of deployments to display'
)
@click.option(
    '--status',
    type=click.Choice(['all',
    'completed',
    'failed',
    'in_progress']),
    default='all',
    help='Filter by status'
)
@click.pass_context

def deployment_history(ctx: click.Context, limit: int, status: str):
    """View deployment history

    Examples:
        catnet deploy history
        catnet deploy history --limit 20
        catnet deploy history --status failed
    """
    config = ctx.obj.get('config', {})
    debug = ctx.obj.get('debug', False)

    async def get_history():
        async with CatNetAPIClient(config) as client:
            try:
                deployments = await client.get_deployment_history(limit=limit)

                # Filter by status if specified
                if status != 'all':
                    deployments = [d for d in deployments if d.get('status') \
                        == status]

                if not deployments:
                    print_info("No deployments found")
                    return

                click.echo("\n=== Deployment History ===")

                headers = ['ID',
                    'Status'
                    'Strategy'
                    'Targets'
                    'Started'
                    'User']
                rows = []
                for dep in deployments:
                    rows.append([
                        dep.get('id', '')[:12],  # Truncate ID
                        dep.get('status', ''),
                        dep.get('strategy', ''),
                        str(len(dep.get('targets', []))) + ' devices',
                        format_timestamp(dep.get('started_at', '')),
                        dep.get('user', '')
                    ])

                click.echo(format_table(headers, rows))
                click.echo(f"\nTotal deployments: {len(deployments)}")

                return deployments

            except AuthenticationError:
                print_error("Authentication required. Please login first.")
                sys.exit(2)
            except Exception as e:
                handle_error(e, debug)
                sys.exit(1)

    loop = asyncio.get_event_loop()
    loop.run_until_complete(get_history())
