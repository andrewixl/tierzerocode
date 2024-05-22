# Import Dependencies
import msal, requests
from datetime import datetime
# Import Models
from ...models import DefenderDevice, Integration
# Import Function Scripts
from .masterlist import *
from .DataCleaner import *

def getCloudflareZeroTrustDevices(access_token, tenant_id):
    url = 'https://api.cloudflare.com/client/v4/accounts/' + tenant_id +'/devices'
    print(url)
    headers = {
        'Authorization': 'Bearer ' + access_token,
        'Content-Type': 'application/json',
    }

    # Make a GET request to the provided url, passing the access token in a header
    graph_result = requests.get(url=url, headers=headers)

    # Print the results in a JSON format
    return graph_result.json()

def updateCloudflareZeroTrustDeviceDatabase(json_data):
    for device_data in json_data['result']:
        # device_id = device_data['id']
        hostname = device_data['name'].lower()
        os_platform = device_data['device_type']

        # [osPlatform_clean, endpointType]
        clean_data = cleanAPIData(os_platform)

        defaults = {
            'hostname': hostname,
            'osPlatform': clean_data[0],
            'endpointType': clean_data[1],
        }
        obj, created = Device.objects.update_or_create(hostname=hostname, defaults=defaults)
        obj.integration.add(Integration.objects.get(integration_type = "Cloudflare Zero Trust"))

def syncCloudflareZeroTrust():
    data = Integration.objects.get(integration_type = "Cloudflare Zero Trust")
    # client_id = data.client_id
    client_secret = data.client_secret
    tenant_id = data.tenant_id
    tenant_domain = data.tenant_domain
    updateCloudflareZeroTrustDeviceDatabase(getCloudflareZeroTrustDevices(client_secret, tenant_id))
    data.last_synced_at = datetime.now()
    data.save()
    return True