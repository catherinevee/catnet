"""
Automation Workflows for CatNet

Handles:
- Automated remediation
- Self-healing operations
- Workflow orchestration
- Event-driven automation
- Scheduled tasks
"""

from typing import Dict, Any, Optional, List, Callable, Union
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import asyncio
import json
from collections import defaultdict, deque
import yaml
import re


class WorkflowState(Enum):
    """Workflow execution states"""

    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class TriggerType(Enum):
    """Workflow trigger types"""

    EVENT = "event"
    SCHEDULE = "schedule"
    MANUAL = "manual"
    CONDITION = "condition"
    WEBHOOK = "webhook"
    API = "api"


class ActionType(Enum):
    """Workflow action types"""

    DEVICE_COMMAND = "device_command"
    CONFIG_CHANGE = "config_change"
    ROLLBACK = "rollback"
    NOTIFICATION = "notification"
    SCRIPT = "script"
    API_CALL = "api_call"
    APPROVAL = "approval"
    WAIT = "wait"
    CONDITION = "condition"


@dataclass
class WorkflowTrigger:
    """Workflow trigger definition"""

    type: TriggerType
    conditions: Dict[str, Any]
    filters: Optional[Dict[str, Any]] = None
    cooldown: timedelta = timedelta(minutes=5)
    enabled: bool = True


@dataclass
class WorkflowAction:
    """Workflow action definition"""

    id: str
    name: str
    type: ActionType
    parameters: Dict[str, Any]
    timeout: timedelta = timedelta(minutes=5)
    retry_count: int = 3
    retry_delay: timedelta = timedelta(seconds=30)
    on_success: Optional[List[str]] = None
    on_failure: Optional[List[str]] = None
    conditions: Optional[Dict[str, Any]] = None


@dataclass
class WorkflowStep:
    """Workflow execution step"""

    action: WorkflowAction
    state: WorkflowState
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    attempts: int = 0


@dataclass
class Workflow:
    """Workflow definition"""

    id: str
    name: str
    description: str
    triggers: List[WorkflowTrigger]
    actions: List[WorkflowAction]
    variables: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)
    enabled: bool = True


@dataclass
class WorkflowExecution:
    """Workflow execution instance"""

    id: str
    workflow_id: str
    state: WorkflowState
    trigger_event: Dict[str, Any]
    started_at: datetime
    completed_at: Optional[datetime] = None
    steps: List[WorkflowStep] = field(default_factory=list)
    context: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None


class WorkflowEngine:
    """
    Workflow automation engine
    """

    def __init__(
        self,
        device_service=None,
        deployment_service=None,
        notification_service=None,
        monitoring_service=None,
    ):
        """
        Initialize workflow engine

        Args:
            device_service: Device management service
            deployment_service: Deployment service
            notification_service: Notification service
            monitoring_service: Monitoring service
        """
        self.device_service = device_service
        self.deployment_service = deployment_service
        self.notification_service = notification_service
        self.monitoring_service = monitoring_service

        # Workflow storage
        self.workflows: Dict[str, Workflow] = {}
        self.executions: Dict[str, WorkflowExecution] = {}
        self.execution_history: List[WorkflowExecution] = []

        # Execution management
        self.running_executions: Dict[str, asyncio.Task] = {}
        self.execution_queue: asyncio.Queue = asyncio.Queue()

        # Event subscriptions
        self.event_subscriptions: Dict[str, List[str]] = defaultdict(list)

        # Scheduled tasks
        self.scheduled_tasks: Dict[str, asyncio.Task] = {}

        # Action handlers
        self.action_handlers: Dict[ActionType, Callable] = {}
        self._register_action_handlers()

        # Initialize default workflows
        self._initialize_default_workflows()

    def _register_action_handlers(self):
        """Register action type handlers"""
        self.action_handlers[ActionType.DEVICE_COMMAND] = self._execute_device_command
        self.action_handlers[ActionType.CONFIG_CHANGE] = self._execute_config_change
        self.action_handlers[ActionType.ROLLBACK] = self._execute_rollback
        self.action_handlers[ActionType.NOTIFICATION] = self._execute_notification
        self.action_handlers[ActionType.SCRIPT] = self._execute_script
        self.action_handlers[ActionType.API_CALL] = self._execute_api_call
        self.action_handlers[ActionType.WAIT] = self._execute_wait
        self.action_handlers[ActionType.CONDITION] = self._execute_condition

    def _initialize_default_workflows(self):
        """Initialize default automation workflows"""
        # Auto-remediation for high CPU
        self.add_workflow(
            Workflow(
                id="auto_remediate_cpu",
                name="Auto-Remediate High CPU",
                description="Automatically remediate high CPU usage",
                triggers=[
                    WorkflowTrigger(
                        type=TriggerType.EVENT,
                        conditions={
                            "event_type": "alert.fired",
                            "alert_name": "high_cpu",
                        },
                        cooldown=timedelta(minutes=15),
                    )
                ],
                actions=[
                    WorkflowAction(
                        id="check_processes",
                        name="Check Running Processes",
                        type=ActionType.DEVICE_COMMAND,
                        parameters={
                            "command": "show processes cpu sorted",
                            "parse_output": True,
                        },
                    ),
                    WorkflowAction(
                        id="analyze_cause",
                        name="Analyze Root Cause",
                        type=ActionType.SCRIPT,
                        parameters={
                            "script": "analyze_cpu_usage.py",
                            "input": "{{check_processes.output}}",
                        },
                    ),
                    WorkflowAction(
                        id="remediate",
                        name="Apply Remediation",
                        type=ActionType.DEVICE_COMMAND,
                        parameters={
                            "command": "{{analyze_cause.remediation_command}}",
                            "confirm": True,
                        },
                        conditions={"analyze_cause.requires_action": True},
                    ),
                    WorkflowAction(
                        id="notify",
                        name="Send Notification",
                        type=ActionType.NOTIFICATION,
                        parameters={
                            "channel": "slack",
                            "message": "CPU remediation completed on {{device_id}}",
                        },
                    ),
                ],
            )
        )

        # Automatic backup before changes
        self.add_workflow(
            Workflow(
                id="auto_backup",
                name="Automatic Backup",
                description="Create backup before configuration changes",
                triggers=[
                    WorkflowTrigger(
                        type=TriggerType.EVENT,
                        conditions={"event_type": "deployment.starting"},
                    )
                ],
                actions=[
                    WorkflowAction(
                        id="create_backup",
                        name="Create Configuration Backup",
                        type=ActionType.DEVICE_COMMAND,
                        parameters={
                            "command": "show running-config",
                            "save_as": "backup_{{timestamp}}.cfg",
                        },
                    ),
                    WorkflowAction(
                        id="verify_backup",
                        name="Verify Backup",
                        type=ActionType.SCRIPT,
                        parameters={
                            "script": "verify_backup.py",
                            "backup_path": "{{create_backup.file_path}}",
                        },
                    ),
                    WorkflowAction(
                        id="proceed_or_abort",
                        name="Proceed with Deployment",
                        type=ActionType.CONDITION,
                        parameters={
                            "condition": "{{verify_backup.success}}",
                            "true_action": "continue",
                            "false_action": "abort",
                        },
                    ),
                ],
            )
        )

        # Compliance check and remediation
        self.add_workflow(
            Workflow(
                id="compliance_check",
                name="Compliance Check and Remediation",
                description="Regular compliance verification and auto-fix",
                triggers=[
                    WorkflowTrigger(
                        type=TriggerType.SCHEDULE,
                        conditions={"cron": "0 2 * * *"},  # Daily at 2 AM
                    )
                ],
                actions=[
                    WorkflowAction(
                        id="scan_configs",
                        name="Scan Device Configurations",
                        type=ActionType.SCRIPT,
                        parameters={
                            "script": "compliance_scan.py",
                            "policy": "security_baseline",
                        },
                    ),
                    WorkflowAction(
                        id="generate_report",
                        name="Generate Compliance Report",
                        type=ActionType.SCRIPT,
                        parameters={
                            "script": "generate_report.py",
                            "scan_results": "{{scan_configs.results}}",
                        },
                    ),
                    WorkflowAction(
                        id="auto_fix",
                        name="Auto-Fix Violations",
                        type=ActionType.CONFIG_CHANGE,
                        parameters={
                            "changes": "{{scan_configs.remediation_commands}}",
                            "approval_required": True,
                        },
                        conditions={"scan_configs.auto_fixable": True},
                    ),
                    WorkflowAction(
                        id="notify_team",
                        name="Notify Team",
                        type=ActionType.NOTIFICATION,
                        parameters={
                            "channel": "email",
                            "recipients": ["compliance@company.com"],
                            "subject": "Daily Compliance Report",
                            "body": "{{generate_report.html}}",
                        },
                    ),
                ],
            )
        )

    def add_workflow(self, workflow: Workflow):
        """
        Add a workflow

        Args:
            workflow: Workflow to add
        """
        self.workflows[workflow.id] = workflow

        # Subscribe to events
        for trigger in workflow.triggers:
            if trigger.type == TriggerType.EVENT:
                event_type = trigger.conditions.get("event_type")
                if event_type:
                    self.event_subscriptions[event_type].append(workflow.id)
            elif trigger.type == TriggerType.SCHEDULE:
                # Schedule workflow
                self._schedule_workflow(workflow)

    def remove_workflow(self, workflow_id: str):
        """
        Remove a workflow

        Args:
            workflow_id: Workflow ID
        """
        if workflow_id in self.workflows:
            workflow = self.workflows[workflow_id]

            # Unsubscribe from events
            for trigger in workflow.triggers:
                if trigger.type == TriggerType.EVENT:
                    event_type = trigger.conditions.get("event_type")
                    if (
                        event_type
                        and workflow_id in self.event_subscriptions[event_type]
                    ):
                        self.event_subscriptions[event_type].remove(workflow_id)

            # Cancel scheduled tasks
            if workflow_id in self.scheduled_tasks:
                self.scheduled_tasks[workflow_id].cancel()
                del self.scheduled_tasks[workflow_id]

            del self.workflows[workflow_id]

    async def trigger_workflow(
        self, workflow_id: str, trigger_event: Dict[str, Any]
    ) -> str:
        """
        Trigger a workflow execution

        Args:
            workflow_id: Workflow ID
            trigger_event: Triggering event data

        Returns:
            Execution ID
        """
        if workflow_id not in self.workflows:
            raise ValueError(f"Workflow {workflow_id} not found")

        workflow = self.workflows[workflow_id]

        if not workflow.enabled:
            return None

        # Create execution
        import uuid

        execution_id = str(uuid.uuid4())[:12]

        execution = WorkflowExecution(
            id=execution_id,
            workflow_id=workflow_id,
            state=WorkflowState.PENDING,
            trigger_event=trigger_event,
            started_at=datetime.utcnow(),
            context=workflow.variables.copy(),
        )

        # Add trigger event to context
        execution.context.update(trigger_event)

        # Store execution
        self.executions[execution_id] = execution

        # Queue for execution
        await self.execution_queue.put(execution_id)

        # Start execution task
        task = asyncio.create_task(self._execute_workflow(execution_id))
        self.running_executions[execution_id] = task

        return execution_id

    async def _execute_workflow(self, execution_id: str):
        """Execute a workflow"""
        execution = self.executions[execution_id]
        workflow = self.workflows[execution.workflow_id]

        try:
            execution.state = WorkflowState.RUNNING

            # Execute actions in sequence
            for action in workflow.actions:
                # Check conditions
                if action.conditions:
                    if not self._evaluate_condition(
                        action.conditions, execution.context
                    ):
                        continue

                # Create step
                step = WorkflowStep(action=action, state=WorkflowState.PENDING)
                execution.steps.append(step)

                # Execute action
                await self._execute_action(step, execution)

                # Check step result
                if step.state == WorkflowState.FAILED:
                    # Handle failure
                    if action.on_failure:
                        # Execute failure actions
                        pass
                    else:
                        # Stop workflow on failure
                        execution.state = WorkflowState.FAILED
                        execution.error = step.error
                        break
                elif step.state == WorkflowState.COMPLETED:
                    # Update context with results
                    if step.result:
                        execution.context[action.id] = step.result

                    # Handle success
                    if action.on_success:
                        # Execute success actions
                        pass

            # Mark as completed if all steps succeeded
            if execution.state == WorkflowState.RUNNING:
                execution.state = WorkflowState.COMPLETED

        except Exception as e:
            execution.state = WorkflowState.FAILED
            execution.error = str(e)

        finally:
            execution.completed_at = datetime.utcnow()

            # Store in history
            self.execution_history.append(execution)

            # Clean up
            if execution_id in self.running_executions:
                del self.running_executions[execution_id]

    async def _execute_action(self, step: WorkflowStep, execution: WorkflowExecution):
        """Execute a workflow action"""
        step.state = WorkflowState.RUNNING
        step.started_at = datetime.utcnow()

        handler = self.action_handlers.get(step.action.type)
        if not handler:
            step.state = WorkflowState.FAILED
            step.error = f"No handler for action type {step.action.type}"
            return

        # Retry logic
        for attempt in range(step.action.retry_count):
            step.attempts = attempt + 1

            try:
                # Execute with timeout
                result = await asyncio.wait_for(
                    handler(step.action.parameters, execution.context),
                    timeout=step.action.timeout.total_seconds(),
                )

                step.result = result
                step.state = WorkflowState.COMPLETED
                break

            except asyncio.TimeoutError:
                step.error = "Action timed out"
                if attempt < step.action.retry_count - 1:
                    await asyncio.sleep(step.action.retry_delay.total_seconds())
                else:
                    step.state = WorkflowState.FAILED

            except Exception as e:
                step.error = str(e)
                if attempt < step.action.retry_count - 1:
                    await asyncio.sleep(step.action.retry_delay.total_seconds())
                else:
                    step.state = WorkflowState.FAILED

        step.completed_at = datetime.utcnow()

    # Action Handlers

    async def _execute_device_command(
        self, parameters: Dict[str, Any], context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute device command action"""
        if not self.device_service:
            raise ValueError("Device service not available")

        # Substitute variables
        command = self._substitute_variables(parameters["command"], context)
        device_id = parameters.get("device_id") or context.get("device_id")

        # Execute command
        output = await self.device_service.execute_command(device_id, command)

        result = {"output": output}

        # Parse output if requested
        if parameters.get("parse_output"):
            # Simple parsing logic
            result["parsed"] = self._parse_output(output)

        # Save output if requested
        if "save_as" in parameters:
            filename = self._substitute_variables(parameters["save_as"], context)
            # Save to file (implementation depends on storage service)
            result["file_path"] = filename

        return result

    async def _execute_config_change(
        self, parameters: Dict[str, Any], context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute configuration change action"""
        if not self.deployment_service:
            raise ValueError("Deployment service not available")

        changes = self._substitute_variables(str(parameters["changes"]), context)
        device_id = parameters.get("device_id") or context.get("device_id")

        # Check if approval required
        if parameters.get("approval_required"):
            # Wait for approval (simplified)
            await asyncio.sleep(1)

        # Apply configuration
        deployment_id = await self.deployment_service.create_deployment(
            name=f"Workflow config change",
            devices=[device_id],
            configuration=changes,
            auto_execute=True,
        )

        return {"deployment_id": deployment_id, "status": "applied"}

    async def _execute_rollback(
        self, parameters: Dict[str, Any], context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute rollback action"""
        if not self.deployment_service:
            raise ValueError("Deployment service not available")

        deployment_id = parameters.get("deployment_id") or context.get("deployment_id")

        # Trigger rollback
        success = await self.deployment_service.rollback_deployment(deployment_id)

        return {"success": success, "rollback_completed": datetime.utcnow().isoformat()}

    async def _execute_notification(
        self, parameters: Dict[str, Any], context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute notification action"""
        if not self.notification_service:
            # Fallback to print
            message = self._substitute_variables(parameters["message"], context)
            print(f"Notification: {message}")
            return {"sent": True, "method": "console"}

        channel = parameters["channel"]
        message = self._substitute_variables(parameters["message"], context)

        # Send notification
        await self.notification_service.send(
            channel=channel, message=message, **parameters
        )

        return {"sent": True, "channel": channel}

    async def _execute_script(
        self, parameters: Dict[str, Any], context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute script action"""
        script = parameters["script"]
        input_data = parameters.get("input")

        if input_data:
            input_data = self._substitute_variables(str(input_data), context)

        # Execute script (simplified - in production use proper sandboxing)
        import subprocess

        result = subprocess.run(
            ["python", script],
            input=input_data.encode() if input_data else None,
            capture_output=True,
            text=True,
            timeout=60,
        )

        return {
            "stdout": result.stdout,
            "stderr": result.stderr,
            "return_code": result.returncode,
        }

    async def _execute_api_call(
        self, parameters: Dict[str, Any], context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute API call action"""
        import aiohttp

        url = self._substitute_variables(parameters["url"], context)
        method = parameters.get("method", "GET")
        headers = parameters.get("headers", {})
        body = parameters.get("body")

        if body:
            body = self._substitute_variables(json.dumps(body), context)
            body = json.loads(body)

        async with aiohttp.ClientSession() as session:
            async with session.request(
                method, url, headers=headers, json=body
            ) as response:
                return {
                    "status_code": response.status,
                    "body": await response.json()
                    if response.content_type == "application/json"
                    else await response.text(),
                }

    async def _execute_wait(
        self, parameters: Dict[str, Any], context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute wait action"""
        duration = parameters.get("duration", 60)
        await asyncio.sleep(duration)
        return {"waited": duration}

    async def _execute_condition(
        self, parameters: Dict[str, Any], context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute conditional action"""
        condition = self._substitute_variables(parameters["condition"], context)

        # Evaluate condition
        try:
            result = eval(condition, {"__builtins__": {}}, context)
        except:
            result = False

        if result:
            action = parameters.get("true_action", "continue")
        else:
            action = parameters.get("false_action", "continue")

        return {"condition_result": result, "action": action}

    # Utility Methods

    def _substitute_variables(self, text: str, context: Dict[str, Any]) -> str:
        """Substitute variables in text"""
        # Simple variable substitution {{var}}
        pattern = r"\{\{([^}]+)\}\}"

        def replace(match):
            path = match.group(1).strip()
            parts = path.split(".")

            value = context
            for part in parts:
                if isinstance(value, dict):
                    value = value.get(part, "")
                else:
                    return ""

            return str(value)

        return re.sub(pattern, replace, text)

    def _evaluate_condition(
        self, conditions: Dict[str, Any], context: Dict[str, Any]
    ) -> bool:
        """Evaluate conditions"""
        for key, expected in conditions.items():
            actual = context.get(key)
            if actual != expected:
                return False
        return True

    def _parse_output(self, output: str) -> Dict[str, Any]:
        """Parse command output"""
        # Simple parsing - would be more sophisticated in production
        lines = output.strip().split("\n")
        return {"lines": lines, "line_count": len(lines)}

    def _schedule_workflow(self, workflow: Workflow):
        """Schedule a workflow"""
        # Implementation depends on scheduler
        pass

    async def handle_event(self, event: Dict[str, Any]):
        """Handle an event that might trigger workflows"""
        event_type = event.get("type")
        if not event_type:
            return

        # Find subscribed workflows
        workflow_ids = self.event_subscriptions.get(event_type, [])

        for workflow_id in workflow_ids:
            if workflow_id in self.workflows:
                await self.trigger_workflow(workflow_id, event)

    def get_execution_status(self, execution_id: str) -> Optional[Dict[str, Any]]:
        """Get workflow execution status"""
        if execution_id not in self.executions:
            return None

        execution = self.executions[execution_id]
        return {
            "id": execution.id,
            "workflow_id": execution.workflow_id,
            "state": execution.state.value,
            "started_at": execution.started_at.isoformat(),
            "completed_at": execution.completed_at.isoformat()
            if execution.completed_at
            else None,
            "steps": [
                {
                    "action": step.action.name,
                    "state": step.state.value,
                    "attempts": step.attempts,
                    "error": step.error,
                }
                for step in execution.steps
            ],
            "error": execution.error,
        }

    def get_workflow_metrics(self) -> Dict[str, Any]:
        """Get workflow execution metrics"""
        total = len(self.execution_history)
        if total == 0:
            return {
                "total_executions": 0,
                "success_rate": 0,
                "average_duration": 0,
                "by_workflow": {},
            }

        successful = sum(
            1 for e in self.execution_history if e.state == WorkflowState.COMPLETED
        )

        durations = []
        for e in self.execution_history:
            if e.completed_at:
                duration = (e.completed_at - e.started_at).total_seconds()
                durations.append(duration)

        by_workflow = defaultdict(lambda: {"total": 0, "successful": 0})
        for e in self.execution_history:
            by_workflow[e.workflow_id]["total"] += 1
            if e.state == WorkflowState.COMPLETED:
                by_workflow[e.workflow_id]["successful"] += 1

        return {
            "total_executions": total,
            "successful_executions": successful,
            "success_rate": successful / total if total > 0 else 0,
            "average_duration": sum(durations) / len(durations) if durations else 0,
            "active_executions": len(self.running_executions),
            "by_workflow": dict(by_workflow),
        }
