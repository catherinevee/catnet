"""
Credential Rotation Background Worker
Schedules and executes automated credential rotations
"""
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from datetime import datetime
import structlog

from src.security.credential_rotation import credential_rotation_engine
from src.db.session import get_db
from src.db.models.credential_rotation import CredentialRotationPolicy

logger = structlog.get_logger()


class CredentialRotationScheduler:
    """
    Background scheduler for automated credential rotations

    Features:
    - Checks for due rotations every 5 minutes
    - Executes rotations based on policy schedule
    - Handles failures gracefully
    - Comprehensive logging
    """

    def __init__(self):
        self.scheduler = AsyncIOScheduler()
        self.check_interval_minutes = 5
        self.is_running = False

    async def start(self):
        """
        Start the rotation scheduler

        Adds a job that runs every 5 minutes to check for due rotations
        """
        if self.is_running:
            logger.warning("Credential rotation scheduler already running")
            return

        # Add job to check for due rotations
        self.scheduler.add_job(
            self.check_due_rotations,
            trigger=IntervalTrigger(minutes=self.check_interval_minutes),
            id="credential_rotation_check",
            replace_existing=True,
            max_instances=1,  # Prevent concurrent executions
            coalesce=True  # Combine missed executions
        )

        self.scheduler.start()
        self.is_running = True

        logger.info(
            "Credential rotation scheduler started",
            check_interval_minutes=self.check_interval_minutes
        )

    async def stop(self):
        """
        Stop the rotation scheduler

        Waits for any running jobs to complete before shutting down
        """
        if not self.is_running:
            logger.warning("Credential rotation scheduler not running")
            return

        logger.info("Stopping credential rotation scheduler")

        self.scheduler.shutdown(wait=True)
        self.is_running = False

        logger.info("Credential rotation scheduler stopped")

    async def check_due_rotations(self):
        """
        Check for policies that need rotation and execute them

        Process:
        1. Query for enabled policies with next_rotation <= now
        2. Execute rotation for each policy
        3. Handle failures gracefully
        4. Update policy next_rotation after successful rotation
        """
        try:
            logger.debug("Checking for due credential rotations")

            async with get_db() as db:
                now = datetime.utcnow()

                # Find policies due for rotation
                policies = await db.query(CredentialRotationPolicy).filter(
                    CredentialRotationPolicy.enabled == True,
                    CredentialRotationPolicy.next_rotation <= now
                ).all()

                if not policies:
                    logger.debug("No credentials due for rotation")
                    return

                logger.info(
                    "Found credentials due for rotation",
                    count=len(policies)
                )

                # Execute rotations
                successful = 0
                failed = 0

                for policy in policies:
                    try:
                        history = await credential_rotation_engine.rotate_device_credentials(
                            device_id=policy.device_id,
                            policy=policy,
                            initiated_by="system"
                        )

                        # Add history to database
                        db.add(history)

                        if history.status.value == "completed":
                            successful += 1
                        else:
                            failed += 1

                    except Exception as e:
                        failed += 1
                        logger.error(
                            "Failed to rotate credentials",
                            policy_id=policy.id,
                            device_id=policy.device_id,
                            error=str(e)
                        )

                # Commit all changes
                await db.commit()

                logger.info(
                    "Rotation check completed",
                    total=len(policies),
                    successful=successful,
                    failed=failed
                )

        except Exception as e:
            logger.error(
                "Error during rotation check",
                error=str(e)
            )

    async def rotate_now(self, device_id: str, policy_id: str, initiated_by: str = "manual"):
        """
        Manually trigger an immediate rotation

        Args:
            device_id: Device to rotate
            policy_id: Policy to use
            initiated_by: User initiating the rotation

        Returns:
            CredentialRotationHistory record
        """
        logger.info(
            "Manual rotation triggered",
            device_id=device_id,
            policy_id=policy_id,
            initiated_by=initiated_by
        )

        async with get_db() as db:
            policy = await db.query(CredentialRotationPolicy).filter(
                CredentialRotationPolicy.id == policy_id
            ).first()

            if not policy:
                logger.error("Policy not found", policy_id=policy_id)
                raise ValueError(f"Policy {policy_id} not found")

            history = await credential_rotation_engine.rotate_device_credentials(
                device_id=device_id,
                policy=policy,
                initiated_by=initiated_by
            )

            db.add(history)
            await db.commit()

            return history

    def get_scheduler_status(self) -> dict:
        """
        Get current scheduler status

        Returns:
            Dictionary with scheduler information
        """
        return {
            "running": self.is_running,
            "check_interval_minutes": self.check_interval_minutes,
            "jobs": [
                {
                    "id": job.id,
                    "name": job.name,
                    "next_run_time": job.next_run_time.isoformat() if job.next_run_time else None
                }
                for job in self.scheduler.get_jobs()
            ] if self.is_running else []
        }


# Global instance
rotation_scheduler = CredentialRotationScheduler()
