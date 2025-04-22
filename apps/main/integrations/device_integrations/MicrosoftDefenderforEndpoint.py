# Import Dependencies
import msal, requests, threading
from django.utils import timezone
# Import Models
from ...models import Integration, Device, MicrosoftDefenderforEndpointDeviceData, DeviceComplianceSettings
# Import Function Scripts
from .ReusedFunctions import *
from ....logger.views import createLog

######################################## Start Get Microsoft Defender for Endpoint Access Token ########################################
def getMicrosoftDefenderforEndpointAccessToken(client_id, client_secret, tenant_id):
    authority = f'https://login.microsoftonline.com/{tenant_id}'
    scope = ['https://api.securitycenter.microsoft.com/.default']
    client = msal.ConfidentialClientApplication(client_id, authority=authority, client_credential=client_secret)
    
    token_result = client.acquire_token_silent(scope, account=None)
    if not token_result:
        token_result = client.acquire_token_for_client(scopes=scope)
    if not token_result or 'access_token' not in token_result:
        raise Exception("Failed to acquire access token")

    access_token = 'Bearer ' + token_result['access_token']
    return access_token
######################################## End Get Microsoft Defender for Endpoint Access Token ########################################

######################################## Start Get Microsoft Defender for Endpoint Devices ########################################
def getMicrosoftDefenderforEndpointDevices(access_token):
    url = 'https://api.securitycenter.microsoft.com/api/machines'
    headers = {'Authorization': access_token}
    # Make a GET request to the provided url, passing the access token in a header
    graph_result = requests.get(url=url, headers=headers)
    # Print the results in a JSON format
    return graph_result.json()
######################################## End Get Microsoft Defender for Endpoint Devices ########################################

######################################## Start Update/Create Microsoft Defender for Endpoint Devices ########################################
def complianceSettings(os_platform):
    try:
        settings = DeviceComplianceSettings.objects.get(os_platform=os_platform)
        return {
            'Cloudflare Zero Trust': settings.cloudflare_zero_trust,
            'CrowdStrike Falcon': settings.crowdstrike_falcon,
            'Microsoft Defender for Endpoint': settings.microsoft_defender_for_endpoint,
            'Microsoft Entra ID': settings.microsoft_entra_id,
            'Microsoft Intune': settings.microsoft_intune,
            'Sophos Central': settings.sophos_central,
            'Qualys': settings.qualys,
        }
    except DeviceComplianceSettings.DoesNotExist:
        return {}
    
def updateMicrosoftDefenderforEndpointDeviceDatabase(json_data):
    for device_data in json_data['value']:
        if device_data.get('onboardingStatus') == 'Onboarded' and not device_data.get('healthStatus') == 'Inactive':
            hostname = (device_data['computerDnsName'].split('.', 1)[0]).lower()
            os_platform = device_data['osPlatform']
            clean_data = cleanAPIData(os_platform)
            
            defaults = {
                'hostname': hostname,
                'osPlatform': clean_data[0],
                'endpointType': clean_data[1],
            }

            obj, created = Device.objects.update_or_create(hostname=hostname, defaults=defaults)
            obj.integration.add(Integration.objects.get(integration_type = "Microsoft Defender for Endpoint"))

            enabled_integrations = Integration.objects.filter(enabled=True)
            os_platform = clean_data[0]
            compliance_settings = complianceSettings(os_platform)
            endpoint_data = [
                obj.integration.filter(integration_type=integration.integration_type).exists()
                for integration in enabled_integrations
            ]
            endpoint_match = [
                compliance_settings.get(integration.integration_type)
                for integration in enabled_integrations
            ]
            obj.compliant = endpoint_data == endpoint_match
            obj.save()

            defaults_all = {
                "id": device_data['id'],
                "mergedIntoMachineId": device_data['mergedIntoMachineId'],
                "isPotentialDuplication": device_data['isPotentialDuplication'],
                "isExcluded": device_data['isExcluded'],
                "exclusionReason": device_data['exclusionReason'],
                "computerDnsName": hostname,
                "firstSeen": device_data['firstSeen'],
                "lastSeen": device_data['lastSeen'],
                "osPlatform": device_data['osPlatform'],
                "osVersion": device_data['osVersion'],
                "osProcessor": device_data['osProcessor'],
                "version": device_data['version'],
                "lastIpAddress": device_data['lastIpAddress'],
                "lastExternalIpAddress": device_data['lastExternalIpAddress'],
                "agentVersion": device_data['agentVersion'],
                "osBuild": device_data['osBuild'],
                "healthStatus": device_data['healthStatus'],
                "deviceValue": device_data['deviceValue'],
                "rbacGroupId": device_data['rbacGroupId'],
                "rbacGroupName": device_data['rbacGroupName'],
                "riskScore": device_data['riskScore'],
                "exposureLevel": device_data['exposureLevel'],
                "isAadJoined": device_data['isAadJoined'],
                "aadDeviceId": device_data['aadDeviceId'],
                # "defenderAvStatus": device_data['defenderAvStatus'],
                "onboardingStatus": device_data['onboardingStatus'],
                "osArchitecture": device_data['osArchitecture'],
                "managedBy": device_data['managedBy'],
                "managedByStatus": device_data['managedByStatus'],
                "vmMetadata": device_data['vmMetadata'],
                "parentDevice": obj
            }
            MicrosoftDefenderforEndpointDeviceData.objects.update_or_create(id=device_data['id'], defaults=defaults_all)

######################################## End Update/Create Microsoft Defender for Endpoint Devices ########################################

######################################## Start Sync Microsoft Defender for Endpoint ########################################
def syncMicrosoftDefenderforEndpoint():
    data = Integration.objects.get(integration_type = "Microsoft Defender for Endpoint")
    updateMicrosoftDefenderforEndpointDeviceDatabase(getMicrosoftDefenderforEndpointDevices(getMicrosoftDefenderforEndpointAccessToken(data.client_id, data.client_secret, data.tenant_id)))
    data.last_synced_at = timezone.now()
    data.save()
    return True
######################################## End Sync Microsoft Defender for Endpoint ########################################

######################################## Start Background Sync Microsoft Defender for Endpoint ########################################
def syncMicrosoftDefenderforEndpointBackground(request):
    def run():
        try:
            syncMicrosoftDefenderforEndpoint()
            createLog(1505,"System Integration","System Integration Event","Superuser",True,"System Integration Sync","Success","Microsoft Defender for Endpoint",request.session['user_email'])
        except Exception as e:
            createLog(1505,"System Integration","System Integration Event","Superuser",True,"System Integration Sync","Failure",f"Microsoft Defender for Endpoint - {e}",request.session['user_email'])
    thread = threading.Thread(target=run)
    thread.start()
######################################## End Background Sync Microsoft Defender for Endpoint ########################################