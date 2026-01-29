from django_tasks import task
from apps.main.integrations.user_integrations.MicrosoftEntraID import syncMicrosoftEntraIDUser
from apps.main.integrations.device_integrations.MicrosoftEntraID import syncMicrosoftEntraIDDevice
from apps.main.integrations.device_integrations.MicrosoftIntune import syncMicrosoftIntuneDevice
from apps.main.integrations.device_integrations.MicrosoftDefenderforEndpoint import syncMicrosoftDefenderforEndpointDevice
from apps.main.integrations.device_integrations.CrowdStrikeFalcon import syncCrowdStrikeFalconDevice
from apps.main.integrations.device_integrations.Tailscale import syncTailscaleDevice
from apps.main.integrations.device_integrations.CloudflareZeroTrust import syncCloudflareZeroTrustDevice
from apps.main.integrations.device_integrations.Qualys import syncQualys
from apps.main.integrations.device_integrations.SophosCentral import syncSophos
from apps.logger.views import createLog
from apps.main.models import Notification
from django.utils import timezone
# from django.contrib import messages

@task(queue_name='default')
def deviceIntegrationSyncTask(user_email, ip_address, user_agent, browser, operating_system, integration, integration_clean, notification_id=None):
    """Run Device Integration Sync in a Background Thread."""
    if notification_id:
        obj = Notification.objects.get(id=notification_id)
        obj.status = "In Progress"
        obj.updated_at = timezone.now()
        obj.save()
    else:
        obj = Notification.objects.create(
            title=f"{integration_clean} Device Integration Sync",
            status="In Progress",
            created_at=timezone.now(),
            updated_at=timezone.now(),
        )
    try:
        #X6969
        print(f"Syncing {integration_clean} devices class started")
        if integration == 'microsoft-entra-id':
            syncMicrosoftEntraIDDevice()
        elif integration == 'microsoft-intune':
            syncMicrosoftIntuneDevice()
        elif integration == 'microsoft-defender-for-endpoint':
            syncMicrosoftDefenderforEndpointDevice()
        elif integration == 'crowdstrike-falcon':
            syncCrowdStrikeFalconDevice()
        elif integration == 'tailscale':
            syncTailscaleDevice()
        elif integration == 'cloudflare-zero-trust':
            syncCloudflareZeroTrustDevice()
        elif integration == 'qualys':
            syncQualys()
        elif integration == 'sophos-central':
            syncSophos()
        print(f"Syncing {integration_clean} devices class completed")

        createLog(None, "1505", "System Integration", "System Integration Event", "Superuser", True, "System Integration Sync", "Success", f"{integration_clean} Device", user_email, ip_address, user_agent, browser, operating_system)
        obj.status = "Success"
        obj.updated_at = timezone.now()
        obj.save()
    except Exception as e:
        createLog(None, "1505", "System Integration", "System Integration Event", "Superuser", True, "System Integration Sync", "Failure", f"{integration_clean} Device - {e}", user_email, ip_address, user_agent, browser, operating_system)
        print(f"Error syncing {integration_clean} devices: {e}")
        obj.status = "Failure"
        obj.updated_at = timezone.now()
        obj.save()


@task(queue_name='default')
def microsoftEntraIDUserSyncTask(user_email, ip_address, user_agent, browser, operating_system, notification_id=None):
    """Run Microsoft Entra ID user sync in a background thread."""
    if notification_id:
        obj = Notification.objects.get(id=notification_id)
        obj.status = "In Progress"
        obj.updated_at = timezone.now()
        obj.save()
    else:
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

# @task(queue_name='default')
# def microsoftEntraIDDeviceSyncTask(user_email, ip_address, user_agent, browser, operating_system):
#     """Run Microsoft Entra ID device sync in a background thread."""
#     obj = Notification.objects.create(
#         title="Microsoft Entra ID Device Integration Sync",
#         status="In Progress",
#         created_at=timezone.now(),
#         updated_at=timezone.now(),
#     )
#     try:
#         print("Syncing Microsoft Entra ID devices class started")
#         syncMicrosoftEntraIDDevice()
#         print("Syncing Microsoft Entra ID devices class completed")
#         createLog(None, "1505", "System Integration", "System Integration Event", "Superuser", True, "System Integration Sync", "Success", "Microsoft Entra ID Device", user_email, ip_address, user_agent, browser, operating_system)
#         obj.status = "Success"
#         obj.updated_at = timezone.now()
#         obj.save()
#         # messages.info(request, 'Microsoft Entra ID Device Integration Sync Success')
#     except Exception as e:
#         createLog(None, "1505", "System Integration", "System Integration Event", "Superuser", True, "System Integration Sync", "Failure", f"Microsoft Entra ID Device - {e}", user_email, ip_address, user_agent, browser, operating_system)
#         obj.status = "Failure"
#         obj.updated_at = timezone.now()
#         obj.save()
#         # messages.error(request, f'Microsoft Entra ID Device Integration Sync Failed: {e}')

# @task(queue_name='default')
# def microsoftIntuneDeviceSyncTask(user_email, ip_address, user_agent, browser, operating_system):
#     """Run Microsoft Intune device sync in a background thread."""
#     obj = Notification.objects.create(
#         title="Microsoft Intune Device Integration Sync",
#         status="In Progress",
#         created_at=timezone.now(),
#         updated_at=timezone.now(),
#     )
#     try:
#         print("Syncing Microsoft Intune devices class started")
#         syncMicrosoftIntuneDevice()
#         print("Syncing Microsoft Intune devices class completed")
#         createLog(None, "1505", "System Integration", "System Integration Event", "Superuser", True, "System Integration Sync", "Success", "Microsoft Intune Device", user_email, ip_address, user_agent, browser, operating_system)
#         obj.status = "Success"
#         obj.updated_at = timezone.now()
#         obj.save()
#         # messages.info(request, 'Microsoft Intune Device Integration Sync Success')
#     except Exception as e:
#         createLog(None, "1505", "System Integration", "System Integration Event", "Superuser", True, "System Integration Sync", "Failure", f"Microsoft Intune Device - {e}", user_email, ip_address, user_agent, browser, operating_system)
#         obj.status = "Failure"
#         obj.updated_at = timezone.now()
#         obj.save()
#         # messages.error(request, f'Microsoft Intune Device Integration Sync Failed: {e}')

# @task(queue_name='default')
# def microsoftDefenderforEndpointDeviceSyncTask(user_email, ip_address, user_agent, browser, operating_system):
#     """Run Microsoft Defender for Endpoint device sync in a background thread."""
#     obj = Notification.objects.create(
#         title="Microsoft Defender for Endpoint Device Integration Sync",
#         status="In Progress",
#         created_at=timezone.now(),
#         updated_at=timezone.now(),
#     )
#     try:
#         print("Syncing Microsoft Defender for Endpoint devices class started")
#         syncMicrosoftDefenderforEndpointDevice()
#         print("Syncing Microsoft Defender for Endpoint devices class completed")
#         createLog(None, "1505", "System Integration", "System Integration Event", "Superuser", True, "System Integration Sync", "Success", "Microsoft Defender for Endpoint Device", user_email, ip_address, user_agent, browser, operating_system)
#         obj.status = "Success"
#         obj.updated_at = timezone.now()
#         obj.save()
#         # messages.error(request, f'Microsoft Defender for Endpoint Device Integration Sync Failed: {e}')
#     except Exception as e:
#         createLog(None, "1505", "System Integration", "System Integration Event", "Superuser", True, "System Integration Sync", "Failure", f"Microsoft Defender for Endpoint Device - {e}", user_email, ip_address, user_agent, browser, operating_system)
#         obj.status = "Failure"
#         obj.updated_at = timezone.now()
#         obj.save()
#         # messages.error(request, f'Microsoft Defender for Endpoint Device Integration Sync Failed: {e}')


# @task(queue_name='default')
# def crowdStrikeFalconDeviceSyncTask(user_email, ip_address, user_agent, browser, operating_system):
#     """Run CrowdStrike Falcon device sync in a background thread."""
#     obj = Notification.objects.create(
#         title="CrowdStrike Falcon Device Integration Sync",
#         status="In Progress",
#         created_at=timezone.now(),
#         updated_at=timezone.now(),
#     )
#     try:
#         print("Syncing CrowdStrike Falcon devices class started")
#         syncCrowdStrikeFalconDevice()
#         print("Syncing CrowdStrike Falcon devices class completed")
#         createLog(None, "1505", "System Integration", "System Integration Event", "Superuser", True, "System Integration Sync", "Success", "CrowdStrike Falcon Device", user_email, ip_address, user_agent, browser, operating_system)
#         obj.status = "Success"
#         obj.updated_at = timezone.now()
#         obj.save()
#         # messages.info(request, 'CrowdStrike Falcon Device Integration Sync Success')
#     except Exception as e:
#         createLog(None, "1505", "System Integration", "System Integration Event", "Superuser", True, "System Integration Sync", "Failure", f"CrowdStrike Falcon Device - {e}", user_email, ip_address, user_agent, browser, operating_system)
#         obj.status = "Failure"
#         obj.updated_at = timezone.now()
#         obj.save()
#         # messages.error(request, f'CrowdStrike Falcon Device Integration Sync Failed: {e}')
    

# @task(queue_name='default')
# def sophosDeviceSyncTask(user_email, ip_address, user_agent, browser, operating_system):
#     """Run Sophos device sync in a background thread."""
#     obj = Notification.objects.create(
#         title="Sophos Device Integration Sync",
#         status="In Progress",
#         created_at=timezone.now(),
#         updated_at=timezone.now(),
#     )
#     try:
#         print("Syncing Sophos devices class started")
#         syncSophosDevice()
#         print("Syncing Sophos devices class completed")
#         createLog(None, "1505", "System Integration", "System Integration Event", "Superuser", True, "System Integration Sync", "Success", "Sophos Device", user_email, ip_address, user_agent, browser, operating_system)
#         obj.status = "Success"
#         obj.updated_at = timezone.now()
#         obj.save()
#         # messages.info(request, 'Sophos Device Integration Sync Success')
#     except Exception as e:
#         createLog(None, "1505", "System Integration", "System Integration Event", "Superuser", True, "System Integration Sync", "Failure", f"Sophos Device - {e}", user_email, ip_address, user_agent, browser, operating_system)
#         obj.status = "Failure"
#         obj.updated_at = timezone.now()
#         obj.save()
#         # messages.error(request, f'Sophos Device Integration Sync Failed: {e}')

# @task(queue_name='default')
# def qualysDeviceSyncTask(user_email, ip_address, user_agent, browser, operating_system):
#     """Run Qualys device sync in a background thread."""
#     obj = Notification.objects.create(
#         title="Qualys Device Integration Sync",
#         status="In Progress",
#         created_at=timezone.now(),
#         updated_at=timezone.now(),
#     )
#     try:
#         print("Syncing Qualys devices class started")
#         syncQualysDevice()
#         print("Syncing Qualys devices class completed")
#         createLog(None, "1505", "System Integration", "System Integration Event", "Superuser", True, "System Integration Sync", "Success", "Qualys Device", user_email, ip_address, user_agent, browser, operating_system)
#         obj.status = "Success"
#         obj.updated_at = timezone.now()
#         obj.save()
#         # messages.info(request, 'Qualys Device Integration Sync Success')
#     except Exception as e:
#         createLog(None, "1505", "System Integration", "System Integration Event", "Superuser", True, "System Integration Sync", "Failure", f"Qualys Device - {e}", user_email, ip_address, user_agent, browser, operating_system)
#         obj.status = "Failure"
#         obj.updated_at = timezone.now()
#         obj.save()
#         # messages.error(request, f'Qualys Device Integration Sync Failed: {e}')

# @task(queue_name='default')
# def cloudflareZeroTrustDeviceSyncTask(user_email, ip_address, user_agent, browser, operating_system):
#     """Run Cloudflare Zero Trust device sync in a background thread."""
#     obj = Notification.objects.create(
#         title="Cloudflare Zero Trust Device Integration Sync",
#         status="In Progress",
#         created_at=timezone.now(),
#         updated_at=timezone.now(),
#     )
#     try:
#         print("Syncing Cloudflare Zero Trust devices class started")
#         syncCloudflareZeroTrustDevice()
#         print("Syncing Cloudflare Zero Trust devices class completed")
#         createLog(None, "1505", "System Integration", "System Integration Event", "Superuser", True, "System Integration Sync", "Success", "Cloudflare Zero Trust Device", user_email, ip_address, user_agent, browser, operating_system)
#         obj.status = "Success"
#         obj.updated_at = timezone.now()
#         obj.save()
#         # messages.info(request, 'Cloudflare Zero Trust Device Integration Sync Success')
#     except Exception as e:
#         createLog(None, "1505", "System Integration", "System Integration Event", "Superuser", True, "System Integration Sync", "Failure", f"Cloudflare Zero Trust Device - {e}", user_email, ip_address, user_agent, browser, operating_system)
#         obj.status = "Failure"
#         obj.updated_at = timezone.now()
#         obj.save()
#         # messages.error(request, f'Cloudflare Zero Trust Device Integration Sync Failed: {e}')

# @task(queue_name='default')
# def microsoftEntraIDUserSyncTaskScheduled():
#     user_email = 'system@tierzerocode.com'
#     ip_address = '127.0.0.1'
#     user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
#     browser = 'Chrome'
#     operating_system = 'Windows'
#     """Run Microsoft Entra ID user sync in a background thread."""
#     obj = Notification.objects.create(
# 		title="Microsoft Entra ID User Integration Sync",
# 		status="In Progress",
# 		created_at=timezone.now(),
# 		updated_at=timezone.now(),
# 	)
#     try:
#         print("Syncing Microsoft Entra ID users class started")
#         syncMicrosoftEntraIDUser()
#         print("Syncing Microsoft Entra ID users class completed")
#         createLog(None, "1505", "System Integration", "System Integration Event", "Superuser", True, "System Integration Sync", "Success", "Microsoft Entra ID User", user_email, ip_address, user_agent, browser, operating_system)
#         obj.status = "Success"
#         obj.updated_at = timezone.now()
#         obj.save()
# 		# messages.info(request, 'Microsoft Entra ID User Integration Sync Success')
#     except Exception as e:
#         createLog(None, "1505", "System Integration", "System Integration Event", "Superuser", True, "System Integration Sync", "Failure", f"Microsoft Entra ID User - {e}", user_email, ip_address, user_agent, browser, operating_system)
#         obj.status = "Failure"
#         obj.updated_at = timezone.now()
#         obj.save()
		# messages.error(request, f'Microsoft Entra ID User Integration Sync Failed: {e}')