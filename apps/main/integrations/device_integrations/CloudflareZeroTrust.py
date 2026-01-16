# Import Dependencies
import requests
from django.utils import timezone
# Import Models
from apps.main.models import Integration, Device
# Import Function Scripts
from apps.main.integrations.device_integrations.ReusedFunctions import *

######################################## Start Get Cloudflare Zero Trust Devices ########################################
def getCloudflareZeroTrustDevices(access_token, tenant_id):
    url = 'https://api.cloudflare.com/client/v4/accounts/' + tenant_id +'/devices'
    headers = {'Authorization': 'Bearer ' + access_token,'Content-Type': 'application/json',}
    graph_result = requests.get(url=url, headers=headers)
    return graph_result.json()
######################################## End Get Cloudflare Zero Trust Devices ########################################

######################################## Start Update/Create Cloudflare Zero Trust Devices ########################################
def updateCloudflareZeroTrustDeviceDatabase(json_data):
    # Loop through the data provided
    for device_data in json_data['result']:
        # Set the hostname and osPlatform variables
        hostname = device_data['name'].lower()
        os_platform = device_data['device_type']
        # [osPlatform_clean, endpointType]
        clean_data = cleanAPIData(os_platform)
        # Prepare data for updating/creating device
        defaults = {
            'hostname': hostname,
            'osPlatform': clean_data[0],
            'endpointType': clean_data[1],
        }
        # Update or Create the Device object
        obj, created = Device.objects.update_or_create(hostname=hostname, defaults=defaults)

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
        if endpoint_data == endpoint_match:
            obj.compliant = True
        else:
            obj.compliant = False
        obj.save()
        
        # Add the Cloudflare Zero Trust Integration to the Device object
        obj.integration.add(Integration.objects.get(integration_type = "Cloudflare Zero Trust"))
######################################## End Update/Create Cloudflare Zero Trust Devices ########################################

######################################## Start Sync Cloudflare Zero Trust ########################################
def syncCloudflareZeroTrustDevice():
    data = Integration.objects.get(integration_type="Cloudflare Zero Trust")
    if not data.client_secret or not data.tenant_id or not data.tenant_domain:
        raise Exception("Cloudflare Zero Trust integration is not properly configured. Missing client_secret or tenant_domain.")

    updateCloudflareZeroTrustDeviceDatabase(getCloudflareZeroTrustDevices(data.client_secret, data.tenant_id))
    data.last_synced_at = timezone.now()
    data.save()
    return True
######################################## End Sync Cloudflare Zero Trust ########################################