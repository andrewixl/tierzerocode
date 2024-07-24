# Import Dependencies
import msal, requests
from datetime import datetime
# Import Models
from ...models import Integration, Device
# Import Function Scripts
from .ReusedFunctions import *

######################################## Start Get Cloudflare Zero Trust Devices ########################################
def getCloudflareZeroTrustDevices(access_token, tenant_id):
    # Set the URL for the request
    url = 'https://api.cloudflare.com/client/v4/accounts/' + tenant_id +'/devices'
    # Set the headers for the request
    headers = {
        'Authorization': 'Bearer ' + access_token,
        'Content-Type': 'application/json',
    }
    # Make a GET request to the provided url, passing the access token and content type in a header
    graph_result = requests.get(url=url, headers=headers)
    # Return the results in a JSON format
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
def syncCloudflareZeroTrust():
    try:
        # Get the Cloudflare Zero Trust Integration data
        data = Integration.objects.get(integration_type = "Cloudflare Zero Trust")
        # Set the variables for the Cloudflare Zero Trust Integration
        client_secret = data.client_secret
        tenant_id = data.tenant_id
        tenant_domain = data.tenant_domain
        # Sync the Cloudflare Zero Trust Integration
        updateCloudflareZeroTrustDeviceDatabase(getCloudflareZeroTrustDevices(client_secret, tenant_id))
        # Update the last synced time
        data.last_synced_at = datetime.now()
        # Save the changes
        data.save()
        # Return True to indicate the sync was successful
        return True
    except Exception as e:
        # Print the error
        print(e)
        # Return False to indicate the sync was unsuccessful
        return False, e
######################################## End Sync Cloudflare Zero Trust ########################################