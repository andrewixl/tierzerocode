# Import Dependencies
import requests, logging
from django.utils import timezone
# Import Models
from ...models import Integration, Device, CrowdStrikeFalconDeviceData, DeviceComplianceSettings
# Import Function Scripts
from .ReusedFunctions import *

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

######################################## Start Get CrowdStrike Falcon Devices ########################################
def getCrowdStrikeDevices(access_token):
    url = 'https://api.crowdstrike.com/devices/queries/devices-scroll/v1'
    headers = {'Authorization': access_token}
    crowdstrike_aids = ((requests.get(url=url, headers=headers)).json())['resources']

    total_devices = len(crowdstrike_aids)
    total_devices_count = total_devices
    device_pagination_arr = [0]
    while total_devices_count > 0:
        if total_devices_count > 5000 and len(device_pagination_arr) == 0:
            device_pagination_arr.append(5000)
            total_devices_count -= 5000
        elif total_devices_count < 5000 and len(device_pagination_arr) == 0:
            device_pagination_arr.append(total_devices_count)
            total_devices_count = 0
        elif total_devices_count > 5000:
            device_pagination_arr.append(5000 + device_pagination_arr[-1])
            total_devices_count -= 5000
        elif total_devices_count < 5000:
            device_pagination_arr.append(total_devices_count + device_pagination_arr[-1])
            total_devices_count = 0
            
    total_crowdstrike_results = []
    for pagination_arr in range(len(device_pagination_arr)):
        print(device_pagination_arr[pagination_arr])
        if pagination_arr == 0:
            pass
        else:
            url = 'https://api.crowdstrike.com/devices/entities/devices/v2'
            headers = {
                'accept': 'application/json',
                'Authorization': access_token,
                'Content-Type': 'application/json',
            }
            body = {'ids': crowdstrike_aids[device_pagination_arr[pagination_arr-1]:device_pagination_arr[pagination_arr]]}
            crowdstrike_result = requests.post(url=url, headers=headers, json=body)
            total_crowdstrike_results.append(crowdstrike_result.json())

    return total_crowdstrike_results
######################################## End Get CrowdStrike Falcon Devices ########################################

######################################## Start Update/Create CrowdStrike Falcon Devices ########################################
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

def updateCrowdStrikeDeviceDatabase(total_crowdstrike_results):
    for crowdstrike_results in total_crowdstrike_results:
        for device_data in crowdstrike_results['resources']:
            if device_data.get('hostname') is None or device_data.get('os_version') is None:
                print("Device Data is None")
                continue

            hostname = device_data.get('hostname').lower()
            os_platform = device_data.get('os_version')

            clean_data = cleanAPIData(os_platform)
            defaults = {
                'hostname': hostname,
                'osPlatform': clean_data[0],
                'endpointType': clean_data[1],
            }
            if not clean_data[1] == 'Mobile':
                continue

            obj, created = Device.objects.update_or_create(hostname=hostname, defaults=defaults)
            obj.integration.add(Integration.objects.get(integration_type="CrowdStrike Falcon"))

            enabled_integrations = Integration.objects.filter(enabled=True)
            compliance_settings = complianceSettings(clean_data[0])
            endpoint_data = [obj.integration.filter(integration_type=integration.integration_type).exists() for integration in enabled_integrations]
            endpoint_match = [compliance_settings.get(integration.integration_type) for integration in enabled_integrations]
            obj.compliant = endpoint_data == endpoint_match
            obj.save()

            defaults_all = {
                "id": device_data.get('device_id'),
                "agent_load_flags": device_data.get('agent_load_flags'),
                "agent_local_time": device_data.get('agent_local_time'),
                "agent_version": device_data.get('agent_version'),
                "base_image_version": device_data.get('base_image_version'),
                "bios_manufacturer": device_data.get('bios_manufacturer'),
                "bios_version": device_data.get('bios_version'),
                "build_number": device_data.get('build_number'),
                "chassis_type": device_data.get('chassis_type'),
                "chassis_type_desc": device_data.get('chassis_type_desc'),
                "cid": device_data.get('cid'),
                "config_id_base": device_data.get('config_id_base'),
                "config_id_build": device_data.get('config_id_build'),
                "config_id_platform": device_data.get('config_id_platform'),
                "connection_ip": device_data.get('connection_ip'),
                "connection_mac_address": device_data.get('connection_mac_address'),
                "cpu_signature": device_data.get('cpu_signature'),
                "cpu_vendor": device_data.get('cpu_vendor'),
                "default_gateway_ip": device_data.get('default_gateway_ip'),
                "deployment_type": device_data.get('deployment_type'),
                "detection_suppression_status": device_data.get('detection_suppression_status'),
                "email": device_data.get('email'),
                "external_ip": device_data.get('external_ip'),
                "first_login_timestamp": device_data.get('first_login_timestamp'),
                "first_seen": device_data.get('first_seen'),
                "group_hash": device_data.get('group_hash'),
                "host_hidden_status": device_data.get('host_hidden_status'),
                "host_utc_offset": device_data.get('host_utc_offset'),
                "hostname": hostname,
                "instance_id": device_data.get('instance_id'),
                "internet_exposure": device_data.get('internet_exposure'),
                "k8s_cluster_git_version": device_data.get('k8s_cluster_git_version'),
                "k8s_cluster_id": device_data.get('k8s_cluster_id'),
                "k8s_cluster_version": device_data.get('k8s_cluster_version'),
                "kernel_version": device_data.get('kernel_version'),
                "last_login_timestamp": device_data.get('last_login_timestamp'),
                "last_login_uid": device_data.get('last_login_uid'),
                "last_login_user": device_data.get('last_login_user'),
                "last_login_user_sid": device_data.get('last_login_user_sid'),
                "last_reboot": device_data.get('last_reboot'),
                "last_seen": device_data.get('last_seen'),
                "linux_sensor_mode": device_data.get('linux_sensor_mode'),
                "local_ip": device_data.get('local_ip'),
                "mac_address": device_data.get('mac_address'),
                "machine_domain": device_data.get('machine_domain'),
                "major_version": device_data.get('major_version'),
                "migration_completed_time": device_data.get('migration_completed_time'),
                "minor_version": device_data.get('minor_version'),
                "modified_timestamp": device_data.get('modified_timestamp'),
                "os_build": device_data.get('os_build'),
                "os_product_name": device_data.get('os_product_name'),
                "os_version": device_data.get('os_version'),
                "platform_id": device_data.get('platform_id'),
                "platform_name": device_data.get('platform_name'),
                "pod_host_ip4": device_data.get('pod_host_ip4'),
                "pod_host_ip6": device_data.get('pod_host_ip6'),
                "pod_hostname": device_data.get('pod_hostname'),
                "pod_id": device_data.get('pod_id'),
                "pod_ip4": device_data.get('pod_ip4'),
                "pod_ip6": device_data.get('pod_ip6'),
                "pod_name": device_data.get('pod_name'),
                "pod_namespace": device_data.get('pod_namespace'),
                "pod_service_account_name": device_data.get('pod_service_account_name'),
                "pointer_size": device_data.get('pointer_size'),
                "product_type": device_data.get('product_type'),
                "product_type_desc": device_data.get('product_type_desc'),
                "provision_status": device_data.get('provision_status'),
                "reduced_functionality_mode": device_data.get('reduced_functionality_mode'),
                "release_group": device_data.get('release_group'),
                "rtr_state": device_data.get('rtr_state'),
                "serial_number": device_data.get('serial_number'),
                "service_pack_major": device_data.get('service_pack_major'),
                "service_pack_minor": device_data.get('service_pack_minor'),
                "service_provider": device_data.get('service_provider'),
                "service_provider_account_id": device_data.get('service_provider_account_id'),
                "site_name": device_data.get('site_name'),
                "status": device_data.get('status'),
                "system_manufacturer": device_data.get('system_manufacturer'),
                "system_product_name": device_data.get('system_product_name'),
                "zone_group": device_data.get('zone_group'),
                "parentDevice": obj
            }
            CrowdStrikeFalconDeviceData.objects.update_or_create(id=device_data['device_id'], defaults=defaults_all)
######################################## End Update/Create CrowdStrike Falcon Devices ########################################

######################################## Start Sync CrowdStrike Falcon ########################################
def syncCrowdStrikeFalcon():
    data = Integration.objects.get(integration_type="CrowdStrike Falcon")
    client_id = data.client_id
    client_secret = data.client_secret
    tenant_id = data.tenant_id
    tenant_domain = data.tenant_domain
    updateCrowdStrikeDeviceDatabase(getCrowdStrikeDevices(getCrowdStrikeAccessToken(client_id, client_secret, tenant_id)))
    data.last_synced_at = timezone.now()
    data.save()

    print("CrowdStrike Falcon Synced Successfully")
    return True

import threading

def syncCrowdStrikeFalconBackground():
    thread = threading.Thread(target=syncCrowdStrikeFalcon)
    thread.start()
