from django_tasks import task
from apps.main.integrations.user_integrations.MicrosoftEntraID import syncMicrosoftEntraIDUser
from apps.logger.views import createLog
from apps.main.models import Notification
from django.utils import timezone
from django.contrib import messages


@task(queue_name='default')
def microsoftEntraIDUserSyncTask(user_email, ip_address, user_agent, browser, operating_system):
    """Run Microsoft Entra ID user sync in a background thread."""
    obj = Notification.objects.create(
		title="Microsoft Entra ID User Integration Sync",
		status="In Progress",
		created_at=timezone.now(),
		updated_at=timezone.now(),
	)
    try:
        print("Syncing Microsoft Entra ID users class started")
        syncMicrosoftEntraIDUser()
        print("Syncing Microsoft Entra ID users class completed")
        createLog(None, "1505", "System Integration", "System Integration Event", "Superuser", True, "System Integration Sync", "Success", "Microsoft Entra ID User", user_email, ip_address, user_agent, browser, operating_system)
        obj.status = "Success"
        obj.updated_at = timezone.now()
        obj.save()
		# messages.info(request, 'Microsoft Entra ID User Integration Sync Success')
    except Exception as e:
        createLog(None, "1505", "System Integration", "System Integration Event", "Superuser", True, "System Integration Sync", "Failure", f"Microsoft Entra ID User - {e}", user_email, ip_address, user_agent, browser, operating_system)
        obj.status = "Failure"
        obj.updated_at = timezone.now()
        obj.save()
		# messages.error(request, f'Microsoft Entra ID User Integration Sync Failed: {e}')

@task(queue_name='default')
def microsoftEntraIDUserSyncTaskScheduled():
    user_email = 'system@tierzerocode.com'
    ip_address = '127.0.0.1'
    user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    browser = 'Chrome'
    operating_system = 'Windows'
    """Run Microsoft Entra ID user sync in a background thread."""
    obj = Notification.objects.create(
		title="Microsoft Entra ID User Integration Sync",
		status="In Progress",
		created_at=timezone.now(),
		updated_at=timezone.now(),
	)
    try:
        print("Syncing Microsoft Entra ID users class started")
        syncMicrosoftEntraIDUser()
        print("Syncing Microsoft Entra ID users class completed")
        createLog(None, "1505", "System Integration", "System Integration Event", "Superuser", True, "System Integration Sync", "Success", "Microsoft Entra ID User", user_email, ip_address, user_agent, browser, operating_system)
        obj.status = "Success"
        obj.updated_at = timezone.now()
        obj.save()
		# messages.info(request, 'Microsoft Entra ID User Integration Sync Success')
    except Exception as e:
        createLog(None, "1505", "System Integration", "System Integration Event", "Superuser", True, "System Integration Sync", "Failure", f"Microsoft Entra ID User - {e}", user_email, ip_address, user_agent, browser, operating_system)
        obj.status = "Failure"
        obj.updated_at = timezone.now()
        obj.save()
		# messages.error(request, f'Microsoft Entra ID User Integration Sync Failed: {e}')