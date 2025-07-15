from typing import Dict, List, Any, Optional
from django.db.models import Q
from .models import DeviceComplianceSettings, Integration, Device

class ComplianceSettingsManager:
    """Manager class for handling compliance settings operations"""
    
    @staticmethod
    def get_compliance_settings_for_platform(os_platform: str) -> Dict[str, bool]:
        """Get compliance settings for a specific OS platform"""
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
    
    @staticmethod
    def get_all_compliance_settings() -> List[Dict[str, Any]]:
        """Get all compliance settings organized by platform"""
        settings_list = []
        
        for setting in DeviceComplianceSettings.objects.all():
            platform_data = {
                'id': setting.id,
                'os_platform': setting.os_platform,
                'integrations': {
                    'Cloudflare Zero Trust': setting.cloudflare_zero_trust,
                    'Crowdstrike Falcon': setting.crowdstrike_falcon,
                    'Microsoft Defender For Endpoint': setting.microsoft_defender_for_endpoint,
                    'Microsoft Entra Id': setting.microsoft_entra_id,
                    'Microsoft Intune': setting.microsoft_intune,
                    'Sophos Central': setting.sophos_central,
                    'Qualys': setting.qualys,
                },
                'created_at': setting.created_at,
                'updated_at': setting.updated_at,
            }
            settings_list.append(platform_data)
        
        return settings_list
    
    @staticmethod
    def update_compliance_settings(platform_id: int, integration_settings: Dict[str, bool]) -> bool:
        """Update compliance settings for a specific platform"""
        try:
            setting = DeviceComplianceSettings.objects.get(id=platform_id)
            
            # Map integration names to model fields
            field_mapping = {
                'Cloudflare Zero Trust': 'cloudflare_zero_trust',
                'Crowdstrike Falcon': 'crowdstrike_falcon',
                'Microsoft Defender For Endpoint': 'microsoft_defender_for_endpoint',
                'Microsoft Entra Id': 'microsoft_entra_id',
                'Microsoft Intune': 'microsoft_intune',
                'Sophos Central': 'sophos_central',
                'Qualys': 'qualys',
            }
            
            # Update each integration setting
            for integration_name, is_required in integration_settings.items():
                if integration_name in field_mapping:
                    field_name = field_mapping[integration_name]
                    setattr(setting, field_name, is_required)
            
            setting.save()
            return True
            
        except DeviceComplianceSettings.DoesNotExist:
            return False
    
    @staticmethod
    def bulk_update_compliance_settings(integration_settings: Dict[str, bool]) -> int:
        """Bulk update compliance settings across all platforms"""
        updated_count = 0
        
        # Map integration names to model fields
        field_mapping = {
            'Cloudflare Zero Trust': 'cloudflare_zero_trust',
            'Crowdstrike Falcon': 'crowdstrike_falcon',
            'Microsoft Defender For Endpoint': 'microsoft_defender_for_endpoint',
            'Microsoft Entra Id': 'microsoft_entra_id',
            'Microsoft Intune': 'microsoft_intune',
            'Sophos Central': 'sophos_central',
            'Qualys': 'qualys',
        }
        
        for setting in DeviceComplianceSettings.objects.all():
            updated = False
            
            for integration_name, is_required in integration_settings.items():
                if integration_name in field_mapping:
                    field_name = field_mapping[integration_name]
                    if getattr(setting, field_name) != is_required:
                        setattr(setting, field_name, is_required)
                        updated = True
            
            if updated:
                setting.save()
                updated_count += 1
        
        return updated_count
    
    @staticmethod
    def reset_compliance_settings_to_defaults() -> int:
        """Reset all compliance settings to default values (all True)"""
        updated_count = 0
        
        for setting in DeviceComplianceSettings.objects.all():
            setting.cloudflare_zero_trust = True
            setting.crowdstrike_falcon = True
            setting.microsoft_defender_for_endpoint = True
            setting.microsoft_entra_id = True
            setting.microsoft_intune = True
            setting.sophos_central = True
            setting.qualys = True
            setting.save()
            updated_count += 1
        
        return updated_count
    
    @staticmethod
    def get_compliance_summary() -> Dict[str, Any]:
        """Get a summary of compliance settings across all platforms"""
        summary = {
            'total_platforms': 0,
            'platforms_with_requirements': 0,
            'platforms_without_requirements': 0,
            'most_common_integrations': {},
            'platform_details': []
        }
        
        integration_counts = {
            'Cloudflare Zero Trust': 0,
            'CrowdStrike Falcon': 0,
            'Microsoft Defender for Endpoint': 0,
            'Microsoft Entra ID': 0,
            'Microsoft Intune': 0,
            'Sophos Central': 0,
            'Qualys': 0,
        }
        
        for setting in DeviceComplianceSettings.objects.all():
            summary['total_platforms'] += 1
            
            platform_integrations = []
            has_requirements = False
            
            # Check each integration
            if setting.cloudflare_zero_trust:
                integration_counts['Cloudflare Zero Trust'] += 1
                platform_integrations.append('Cloudflare Zero Trust')
                has_requirements = True
            
            if setting.crowdstrike_falcon:
                integration_counts['CrowdStrike Falcon'] += 1
                platform_integrations.append('CrowdStrike Falcon')
                has_requirements = True
            
            if setting.microsoft_defender_for_endpoint:
                integration_counts['Microsoft Defender for Endpoint'] += 1
                platform_integrations.append('Microsoft Defender for Endpoint')
                has_requirements = True
            
            if setting.microsoft_entra_id:
                integration_counts['Microsoft Entra ID'] += 1
                platform_integrations.append('Microsoft Entra ID')
                has_requirements = True
            
            if setting.microsoft_intune:
                integration_counts['Microsoft Intune'] += 1
                platform_integrations.append('Microsoft Intune')
                has_requirements = True
            
            if setting.sophos_central:
                integration_counts['Sophos Central'] += 1
                platform_integrations.append('Sophos Central')
                has_requirements = True
            
            if setting.qualys:
                integration_counts['Qualys'] += 1
                platform_integrations.append('Qualys')
                has_requirements = True
            
            if has_requirements:
                summary['platforms_with_requirements'] += 1
            else:
                summary['platforms_without_requirements'] += 1
            
            summary['platform_details'].append({
                'platform': setting.os_platform,
                'integrations': platform_integrations,
                'has_requirements': has_requirements,
                'updated_at': setting.updated_at
            })
        
        # Sort integrations by count
        summary['most_common_integrations'] = dict(
            sorted(integration_counts.items(), key=lambda x: x[1], reverse=True)
        )
        
        return summary

class DeviceComplianceChecker:
    """Utility class for checking device compliance"""
    
    @staticmethod
    def check_device_compliance(device: Device) -> Dict[str, Any]:
        """Check compliance for a specific device"""
        if not device.osPlatform:
            return {
                'compliant': False,
                'reason': 'No OS platform specified',
                'missing_integrations': [],
                'required_integrations': []
            }
        
        # Get compliance settings for the device's OS platform
        compliance_settings = ComplianceSettingsManager.get_compliance_settings_for_platform(device.osPlatform)
        
        if not compliance_settings:
            return {
                'compliant': True,
                'reason': 'No compliance requirements for this platform',
                'missing_integrations': [],
                'required_integrations': []
            }
        
        # Get device's current integrations
        device_integrations = set(device.integration.filter(enabled=True).values_list('integration_type', flat=True))
        
        # Check which integrations are required but missing
        missing_integrations = []
        required_integrations = []
        
        for integration_name, is_required in compliance_settings.items():
            if is_required:
                required_integrations.append(integration_name)
                if integration_name not in device_integrations:
                    missing_integrations.append(integration_name)
        
        # Device is compliant if no integrations are missing
        is_compliant = len(missing_integrations) == 0
        
        return {
            'compliant': is_compliant,
            'reason': 'Missing required integrations' if missing_integrations else 'All requirements met',
            'missing_integrations': missing_integrations,
            'required_integrations': required_integrations,
            'current_integrations': list(device_integrations)
        }
    
    @staticmethod
    def get_compliance_report() -> Dict[str, Any]:
        """Generate a comprehensive compliance report"""
        report = {
            'total_devices': 0,
            'compliant_devices': 0,
            'non_compliant_devices': 0,
            'compliance_by_platform': {},
            'missing_integrations_summary': {},
            'devices_needing_attention': []
        }
        
        devices = Device.objects.all()
        
        for device in devices:
            report['total_devices'] += 1
            compliance_result = DeviceComplianceChecker.check_device_compliance(device)
            
            if compliance_result['compliant']:
                report['compliant_devices'] += 1
            else:
                report['non_compliant_devices'] += 1
                report['devices_needing_attention'].append({
                    'hostname': device.hostname,
                    'platform': device.osPlatform,
                    'missing_integrations': compliance_result['missing_integrations'],
                    'reason': compliance_result['reason']
                })
            
            # Track compliance by platform
            platform = device.osPlatform or 'Unknown'
            if platform not in report['compliance_by_platform']:
                report['compliance_by_platform'][platform] = {
                    'total': 0,
                    'compliant': 0,
                    'non_compliant': 0
                }
            
            report['compliance_by_platform'][platform]['total'] += 1
            if compliance_result['compliant']:
                report['compliance_by_platform'][platform]['compliant'] += 1
            else:
                report['compliance_by_platform'][platform]['non_compliant'] += 1
            
            # Track missing integrations
            for missing_integration in compliance_result['missing_integrations']:
                if missing_integration not in report['missing_integrations_summary']:
                    report['missing_integrations_summary'][missing_integration] = 0
                report['missing_integrations_summary'][missing_integration] += 1
        
        # Calculate compliance percentage
        if report['total_devices'] > 0:
            report['compliance_percentage'] = (report['compliant_devices'] / report['total_devices']) * 100
        else:
            report['compliance_percentage'] = 0
        
        return report 