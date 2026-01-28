from django.core.management.base import BaseCommand
from django.utils import timezone
from apps.main.tasks import deviceIntegrationSyncTask
from apps.main.models import Notification
import logging

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Sync CrowdStrike Falcon devices automatically'

    def handle(self, *args, **options):
        """Enqueue the CrowdStrike Falcon device sync task"""
        self.stdout.write('Enqueueing CrowdStrike Falcon device sync task...')
        
        # System values for management command execution
        user_email = 'system@tierzerocode.com'
        ip_address = '127.0.0.1'
        user_agent = 'Django Management Command'
        browser = 'System'
        operating_system = 'System'
        integration = 'crowdstrike-falcon'
        integration_clean = 'CrowdStrike Falcon'
        
        # Create notification for tracking
        notification = Notification.objects.create(
            title=f"{integration_clean} Device Integration Sync (Automated)",
            status="Queued",
            created_at=timezone.now(),
            updated_at=timezone.now(),
        )
        
        try:
            # Enqueue the task with notification ID
            result = deviceIntegrationSyncTask.enqueue(
                user_email, ip_address, user_agent, browser, operating_system, integration, integration_clean, notification.id
            )
            
            self.stdout.write(
                self.style.SUCCESS(
                    f'CrowdStrike Falcon device sync task enqueued successfully! Task ID: {result.id}'
                )
            )
            
        except Exception as e:
            # Update notification to failure
            notification.status = "Failure"
            notification.updated_at = timezone.now()
            notification.save()
            
            error_msg = f'Failed to enqueue CrowdStrike Falcon device sync task: {str(e)}'
            self.stdout.write(
                self.style.ERROR(error_msg)
            )
            logger.error(error_msg)
            
            # Re-raise the exception for proper error handling
            raise
