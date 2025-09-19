import pytest
import asyncio
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, AsyncMock
from src.automation.workflows import (
    WorkflowEngine,
    Workflow,
    WorkflowStep,
    StepType,
    WorkflowTrigger,
    TriggerType,
    WorkflowExecution,
    ExecutionStatus,
    WorkflowBuilder,
    RemediationWorkflows
)


class TestWorkflow:
    def test_workflow_creation(self):
        workflow = Workflow(
            id="test_workflow",
            name="Test Workflow",
            description="Test workflow description",
            trigger=WorkflowTrigger(
                type=TriggerType.MANUAL,
                conditions={}
            ),
            steps=[],
            enabled=True
        )

        assert workflow.id == "test_workflow"
        assert workflow.name == "Test Workflow"
        assert workflow.enabled
        assert workflow.trigger.type == TriggerType.MANUAL

    def test_workflow_with_steps(self):
        steps = [
            WorkflowStep(
                id="step1",
                name="Check Device",
                type=StepType.CONDITION,
                parameters={"condition": "device.status == 'up'"}
            ),
            WorkflowStep(
                id="step2",
                name="Send Notification",
                type=StepType.NOTIFICATION,
                parameters={"channel": "slack", "message": "Device is up"}
            )
        ]

        workflow = Workflow(
            id="test_workflow",
            name="Test Workflow",
            trigger=WorkflowTrigger(type=TriggerType.EVENT),
            steps=steps
        )

        assert len(workflow.steps) == 2
        assert workflow.steps[0].type == StepType.CONDITION
        assert workflow.steps[1].type == StepType.NOTIFICATION


class TestWorkflowTrigger:
    def test_event_trigger(self):
        trigger = WorkflowTrigger(
            type=TriggerType.EVENT,
            conditions={
                "event_type": "device.down",
                "severity": "critical"
            }
        )

        assert trigger.type == TriggerType.EVENT
        assert trigger.conditions["event_type"] == "device.down"

    def test_schedule_trigger(self):
        trigger = WorkflowTrigger(
            type=TriggerType.SCHEDULE,
            conditions={
                "cron": "0 2 * * *",  # Daily at 2 AM
                "timezone": "UTC"
            }
        )

        assert trigger.type == TriggerType.SCHEDULE
        assert trigger.conditions["cron"] == "0 2 * * *"

    def test_threshold_trigger(self):
        trigger = WorkflowTrigger(
            type=TriggerType.THRESHOLD,
            conditions={
                "metric": "cpu_usage",
                "operator": ">",
                "value": 90,
                "duration": 300  # 5 minutes
            }
        )

        assert trigger.type == TriggerType.THRESHOLD
        assert trigger.conditions["value"] == 90


class TestWorkflowEngine:
    @pytest.mark.asyncio
    async def test_register_workflow(self):
        engine = WorkflowEngine()

        workflow = Workflow(
            id="test_workflow",
            name="Test Workflow",
            trigger=WorkflowTrigger(type=TriggerType.MANUAL),
            steps=[]
        )

        success = await engine.register_workflow(workflow)

        assert success
        assert "test_workflow" in engine.workflows

    @pytest.mark.asyncio
    async def test_trigger_manual_workflow(self):
        engine = WorkflowEngine()

        workflow = Workflow(
            id="manual_workflow",
            name="Manual Workflow",
            trigger=WorkflowTrigger(type=TriggerType.MANUAL),
            steps=[
                WorkflowStep(
                    id="step1",
                    name="Log Message",
                    type=StepType.NOTIFICATION,
                    parameters={"message": "Workflow triggered"}
                )
            ]
        )

        await engine.register_workflow(workflow)

        execution_id = await engine.trigger_workflow(
            "manual_workflow",
            {"user": "test_user"}
        )

        assert execution_id is not None
        assert execution_id in engine.executions

    @pytest.mark.asyncio
    async def test_execute_condition_step(self):
        engine = WorkflowEngine()

        step = WorkflowStep(
            id="condition_step",
            name="Check Condition",
            type=StepType.CONDITION,
            parameters={"expression": "context['value'] > 10"}
        )

        context = {"value": 15}

        result = await engine._execute_step(step, context)

        assert result["success"] is True
        assert result["condition_met"] is True

    @pytest.mark.asyncio
    async def test_execute_device_command_step(self):
        engine = WorkflowEngine()

        with patch.object(engine, '_execute_device_command', new_callable=AsyncMock) as mock_execute:
            mock_execute.return_value = {"output": "Command executed"}

            step = WorkflowStep(
                id="device_step",
                name="Execute Command",
                type=StepType.DEVICE_COMMAND,
                parameters={
                    "device_id": "device123",
                    "command": "show version"
                }
            )

            result = await engine._execute_step(step, {})

            mock_execute.assert_called_once()
            assert result["output"] == "Command executed"

    @pytest.mark.asyncio
    async def test_execute_api_call_step(self):
        engine = WorkflowEngine()

        with patch('aiohttp.ClientSession') as mock_session:
            mock_response = Mock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value={"status": "success"})

            mock_session.return_value.__aenter__.return_value.request = AsyncMock(
                return_value=mock_response
            )
            mock_response.__aenter__ = AsyncMock(return_value=mock_response)
            mock_response.__aexit__ = AsyncMock(return_value=None)

            step = WorkflowStep(
                id="api_step",
                name="Call API",
                type=StepType.API_CALL,
                parameters={
                    "url": "https://api.example.com/status",
                    "method": "GET"
                }
            )

            result = await engine._execute_step(step, {})

            assert result["status_code"] == 200
            assert result["response"]["status"] == "success"

    @pytest.mark.asyncio
    async def test_workflow_execution_flow(self):
        """Test complete workflow execution with multiple steps"""

        engine = WorkflowEngine()

        workflow = Workflow(
            id="complex_workflow",
            name="Complex Workflow",
            trigger=WorkflowTrigger(type=TriggerType.MANUAL),
            steps=[
                WorkflowStep(
                    id="step1",
                    name="Check Condition",
                    type=StepType.CONDITION,
                    parameters={"expression": "True"}
                ),
                WorkflowStep(
                    id="step2",
                    name="Log Success",
                    type=StepType.NOTIFICATION,
                    parameters={"message": "Condition met"},
                    depends_on=["step1"]
                )
            ]
        )

        await engine.register_workflow(workflow)

        execution_id = await engine.trigger_workflow(
            "complex_workflow",
            {"test": "data"}
        )

        # Wait for execution to complete
        await asyncio.sleep(0.1)

        execution = engine.executions.get(execution_id)
        assert execution is not None
        assert len(execution.step_results) == 2

    @pytest.mark.asyncio
    async def test_workflow_with_parallel_steps(self):
        engine = WorkflowEngine()

        workflow = Workflow(
            id="parallel_workflow",
            name="Parallel Workflow",
            trigger=WorkflowTrigger(type=TriggerType.MANUAL),
            steps=[
                WorkflowStep(
                    id="parallel1",
                    name="Parallel Step 1",
                    type=StepType.NOTIFICATION,
                    parameters={"message": "Step 1"}
                ),
                WorkflowStep(
                    id="parallel2",
                    name="Parallel Step 2",
                    type=StepType.NOTIFICATION,
                    parameters={"message": "Step 2"}
                ),
                WorkflowStep(
                    id="final",
                    name="Final Step",
                    type=StepType.NOTIFICATION,
                    parameters={"message": "Done"},
                    depends_on=["parallel1", "parallel2"]
                )
            ]
        )

        await engine.register_workflow(workflow)

        execution_id = await engine.trigger_workflow("parallel_workflow", {})

        await asyncio.sleep(0.1)

        execution = engine.executions.get(execution_id)
        assert len(execution.step_results) == 3

    @pytest.mark.asyncio
    async def test_workflow_error_handling(self):
        engine = WorkflowEngine()

        workflow = Workflow(
            id="error_workflow",
            name="Error Workflow",
            trigger=WorkflowTrigger(type=TriggerType.MANUAL),
            steps=[
                WorkflowStep(
                    id="error_step",
                    name="Error Step",
                    type=StepType.CONDITION,
                    parameters={"expression": "undefined_variable"},
                    on_error="continue"
                ),
                WorkflowStep(
                    id="recovery_step",
                    name="Recovery Step",
                    type=StepType.NOTIFICATION,
                    parameters={"message": "Recovered from error"}
                )
            ]
        )

        await engine.register_workflow(workflow)

        execution_id = await engine.trigger_workflow("error_workflow", {})

        await asyncio.sleep(0.1)

        execution = engine.executions.get(execution_id)
        assert execution.status in [ExecutionStatus.COMPLETED, ExecutionStatus.FAILED]
        assert len(execution.step_results) >= 1


class TestWorkflowBuilder:
    def test_build_simple_workflow(self):
        builder = WorkflowBuilder("simple_workflow", "Simple Workflow")

        workflow = (
            builder
            .with_trigger(TriggerType.MANUAL)
            .add_step(
                id="step1",
                name="First Step",
                type=StepType.NOTIFICATION,
                parameters={"message": "Hello"}
            )
            .build()
        )

        assert workflow.id == "simple_workflow"
        assert len(workflow.steps) == 1
        assert workflow.trigger.type == TriggerType.MANUAL

    def test_build_workflow_with_conditions(self):
        builder = WorkflowBuilder("conditional_workflow", "Conditional Workflow")

        workflow = (
            builder
            .with_trigger(TriggerType.EVENT, {"event_type": "alert"})
            .add_condition("check_severity", "Check Severity", "context['severity'] == 'high'")
            .add_device_command(
                "restart_interface",
                "Restart Interface",
                device_id="device123",
                command="interface restart",
                depends_on=["check_severity"]
            )
            .build()
        )

        assert len(workflow.steps) == 2
        assert workflow.steps[0].type == StepType.CONDITION
        assert workflow.steps[1].depends_on == ["check_severity"]


class TestRemediationWorkflows:
    @pytest.mark.asyncio
    async def test_interface_flapping_remediation(self):
        remediation = RemediationWorkflows()

        workflow = remediation.interface_flapping_remediation()

        assert workflow.name == "Interface Flapping Remediation"
        assert workflow.trigger.type == TriggerType.EVENT
        assert workflow.trigger.conditions["event_type"] == "interface.flapping"

        # Verify workflow has expected steps
        step_types = [step.type for step in workflow.steps]
        assert StepType.DEVICE_COMMAND in step_types
        assert StepType.WAIT in step_types
        assert StepType.NOTIFICATION in step_types

    @pytest.mark.asyncio
    async def test_high_cpu_remediation(self):
        remediation = RemediationWorkflows()

        workflow = remediation.high_cpu_remediation()

        assert workflow.name == "High CPU Usage Remediation"
        assert workflow.trigger.type == TriggerType.THRESHOLD
        assert workflow.trigger.conditions["metric"] == "cpu_usage"
        assert workflow.trigger.conditions["value"] == 90

    @pytest.mark.asyncio
    async def test_config_compliance_remediation(self):
        remediation = RemediationWorkflows()

        workflow = remediation.config_compliance_remediation()

        assert workflow.name == "Configuration Compliance Remediation"
        assert workflow.trigger.type == TriggerType.SCHEDULE
        assert workflow.trigger.conditions["cron"] == "0 0 * * 0"  # Weekly


class TestWorkflowExecution:
    def test_execution_creation(self):
        execution = WorkflowExecution(
            id="exec123",
            workflow_id="workflow123",
            trigger_data={"user": "test"},
            started_at=datetime.now()
        )

        assert execution.id == "exec123"
        assert execution.status == ExecutionStatus.PENDING
        assert execution.trigger_data["user"] == "test"

    def test_execution_status_transitions(self):
        execution = WorkflowExecution(
            id="exec123",
            workflow_id="workflow123",
            trigger_data={},
            started_at=datetime.now()
        )

        # Start execution
        execution.status = ExecutionStatus.IN_PROGRESS
        assert execution.status == ExecutionStatus.IN_PROGRESS

        # Complete execution
        execution.status = ExecutionStatus.COMPLETED
        execution.completed_at = datetime.now()
        assert execution.status == ExecutionStatus.COMPLETED
        assert execution.completed_at is not None

    def test_execution_with_error(self):
        execution = WorkflowExecution(
            id="exec123",
            workflow_id="workflow123",
            trigger_data={},
            started_at=datetime.now()
        )

        execution.status = ExecutionStatus.FAILED
        execution.error = "Step 2 failed: Connection timeout"

        assert execution.status == ExecutionStatus.FAILED
        assert "Connection timeout" in execution.error


class TestWorkflowIntegration:
    @pytest.mark.asyncio
    async def test_end_to_end_remediation_workflow(self):
        """Test a complete remediation workflow execution"""

        engine = WorkflowEngine()

        # Create interface flapping remediation workflow
        remediation = RemediationWorkflows()
        workflow = remediation.interface_flapping_remediation()

        await engine.register_workflow(workflow)

        # Simulate interface flapping event
        event = {
            "event_type": "interface.flapping",
            "device_id": "switch123",
            "interface": "GigabitEthernet1/0/1",
            "flap_count": 5,
            "timestamp": datetime.now().isoformat()
        }

        # Mock device command execution
        with patch.object(engine, '_execute_device_command', new_callable=AsyncMock) as mock_cmd:
            mock_cmd.return_value = {"success": True, "output": "Interface disabled"}

            # Trigger workflow
            execution_id = await engine.trigger_workflow(workflow.id, event)

            await asyncio.sleep(0.2)  # Wait for execution

            execution = engine.executions.get(execution_id)
            assert execution is not None
            assert mock_cmd.called

    @pytest.mark.asyncio
    async def test_scheduled_workflow_execution(self):
        """Test scheduled workflow triggering"""

        engine = WorkflowEngine()

        # Create a scheduled backup workflow
        workflow = Workflow(
            id="backup_workflow",
            name="Scheduled Backup",
            trigger=WorkflowTrigger(
                type=TriggerType.SCHEDULE,
                conditions={"cron": "*/5 * * * *"}  # Every 5 minutes
            ),
            steps=[
                WorkflowStep(
                    id="backup",
                    name="Backup Configs",
                    type=StepType.SCRIPT,
                    parameters={"script": "backup_all_devices.py"}
                )
            ]
        )

        await engine.register_workflow(workflow)

        # Verify workflow is registered for scheduling
        assert workflow.id in engine.workflows
        assert workflow.trigger.type == TriggerType.SCHEDULE