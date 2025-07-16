from django.core.management.base import BaseCommand
from django.utils import timezone
from apps.main.integrations.user_integrations.MicrosoftEntraID import syncMicrosoftEntraIDUsers
from apps.main.models import Notification
import logging

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Sync Microsoft Entra ID users automatically'

    def handle(self, *args, **options):
        """Run the Microsoft Entra ID user sync"""
        self.stdout.write('Starting Microsoft Entra ID user sync...')
        
        # Create notification for tracking
        notification = Notification.objects.create(
            title="Microsoft Entra ID User Integration Sync (Automated)",
            status="In Progress",
            created_at=timezone.now(),
            updated_at=timezone.now(),
        )
        
        try:
            # Run the sync
            syncMicrosoftEntraIDUsers()
            
            # Update notification to success
            notification.status = "Success"
            notification.updated_at = timezone.now()
            notification.save()
            
            self.stdout.write(
                self.style.SUCCESS('Microsoft Entra ID user sync completed successfully!')
            )
            
        except Exception as e:
            # Update notification to failure
            notification.status = "Failure"
            notification.updated_at = timezone.now()
            notification.save()
            
            error_msg = f'Microsoft Entra ID user sync failed: {str(e)}'
            self.stdout.write(
                self.style.ERROR(error_msg)
            )
            logger.error(error_msg)
            
            # Re-raise the exception for proper error handling
            raise 