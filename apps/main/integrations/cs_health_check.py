# Import Dependencies
import requests, logging
from django.utils import timezone
# Import Models
# from ...models import Integration, Device, CrowdStrikeFalconDeviceData, DeviceComplianceSettings
from ..models import Integration, CrowdStrikeFalconPreventionPolicy, CrowdStrikeFalconPreventionPolicySetting
# Import Function Scripts
# from .ReusedFunctions import *

# Set the logger
# logger = logging.getLogger('custom_logger')

######################################## Start Get CrowdStrike Falcon Access Token ########################################
def getCrowdStrikeAccessToken(client_id, client_secret, tenant_id):
    auth_url = 'https://api.crowdstrike.com/oauth2/token'
    auth_payload = {'client_id': client_id, 'client_secret': client_secret}
    try:
        response = requests.post(auth_url, data=auth_payload)
        if response.status_code == 200 or response.status_code == 201:
            return 'Bearer ' + response.json()['access_token']
        else:
            print("Failed to authenticate. Status code:", response.status_code)
            print("Response:", response.text)
    except Exception as e:
        print("An error occurred:", str(e))
######################################## End Get CrowdStrike Falcon Access Token ########################################

######################################## Start Get CrowdStrike Falcon Prevention Policies ########################################
def getCrowdStrikeFalconPreventionPolicies(access_token):
    print("Querying CrowdStrike Falcon Policies")
    url = 'https://api.crowdstrike.com/policy/combined/prevention/v1'
    headers = {'Authorization': access_token}
    prevention_policies = ((requests.get(url=url, headers=headers)).json())['resources']
    return prevention_policies
######################################## End Get CrowdStrike Falcon Prevention Policies ########################################

######################################## Start Update/Create CrowdStrike Falcon Devices ########################################
def updateCrowdStrikePreventionPolicyDatabase(prevention_policies):
    for prevention_policy in prevention_policies:
        defaults = {
            'id': prevention_policy.get('id'),
            'name': prevention_policy.get('name'),
            'platform_name': prevention_policy.get('platform_name'),
            'enabled': prevention_policy.get('enabled'),
        }
        obj, created = CrowdStrikeFalconPreventionPolicy.objects.update_or_create(id=prevention_policy.get('id'), defaults=defaults)
        obj.save()

        for prevention_policy_setting in prevention_policy.get('prevention_settings'):
            settings = prevention_policy_setting['settings']
            for setting in settings:
                defaults_settings = {
                    'id': prevention_policy.get('id') + "--" + setting.get('id'),
                    'name': setting.get('name'),
                    'description': setting.get('description'),
                    'value': setting.get('value'),
                    'prevention_policy': obj
                }
                obj2, created = CrowdStrikeFalconPreventionPolicySetting.objects.update_or_create(id=prevention_policy_setting.get('id'), defaults=defaults_settings)
                obj2.save()
    ######################################## End Update/Create CrowdStrike Falcon Devices ########################################

######################################## Start Sync CrowdStrike Falcon ########################################
def syncCrowdStrikeFalconHealthCheck():
    data = Integration.objects.get(integration_type="CrowdStrike Falcon")
    client_id = data.client_id
    client_secret = data.client_secret
    tenant_id = data.tenant_id
    tenant_domain = data.tenant_domain
    updateCrowdStrikePreventionPolicyDatabase(getCrowdStrikeFalconPreventionPolicies(getCrowdStrikeAccessToken(client_id, client_secret, tenant_id)))
    # updateCrowdStrikeDeviceDatabase(getCrowdStrikeDevices(getCrowdStrikeAccessToken(client_id, client_secret, tenant_id)))
    # data.last_synced_at = timezone.now()
    # data.save()

    print("CrowdStrike Falcon Health Check Synced Successfully")
    return True

import threading

def syncCrowdStrikeFalconHealthCheckBackground():
    thread = threading.Thread(target=syncCrowdStrikeFalconHealthCheck)
    thread.start()
