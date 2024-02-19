from django.db import models

class Device(models.Model):
    hostname = models.CharField(max_length = 50, null=True)

    def __str__(self):
        return self.hostname

class IntuneIntegration(models.Model):
    client_id = models.CharField(max_length = 50, null=True)
    client_secret = models.CharField(max_length = 50, null=True)
    tenant_id = models.CharField(max_length = 50, null=True)
    tenant_domain = models.CharField(max_length = 50, null=True)

    def __str__(self):
        return 'Microsoft Intune (' + self.tenant_domain + ')'

class SophosIntegration(models.Model):
    client_id = models.CharField(max_length = 100, null=True)
    client_secret = models.CharField(max_length = 200, null=True)
    tenant_id = models.CharField(max_length = 100, null=True)
    tenant_domain = models.CharField(max_length = 50, null=True)

    def __str__(self):
        return 'Sophos Central (' + self.tenant_domain + ')'

# DeviceManagementManagedDevices.Read.All
class IntuneDevice(models.Model):
    id = models.CharField(max_length = 100, primary_key=True)
    userId = models.CharField(max_length = 50, null=True)
    deviceName = models.CharField(max_length = 100, null=True)
    managedDeviceOwnerType = models.CharField(max_length = 25, null=True)
    enrolledDateTime = models.DateTimeField(null=True)
    lastSyncDateTime = models.DateTimeField(null=True)
    operatingSystem = models.CharField(max_length = 25, null=True)
    complianceState = models.CharField(max_length = 25, null=True)
    jailBroken = models.CharField(max_length = 25, null=True)
    managementAgent = models.CharField(max_length = 20, null=True)
    osVersion = models.CharField(max_length = 25, null=True)
    easActivated = models.BooleanField(null=True)
    easDeviceId = models.CharField(max_length = 50, null=True)
    easActivationDateTime = models.DateTimeField(null=True)
    azureADRegistered = models.BooleanField(null=True)
    deviceEnrollmentType = models.CharField(max_length = 50, null=True)
    activationLockBypassCode = models.CharField(max_length = 50, null=True)
    emailAddress = models.EmailField(max_length = 100, null=True)
    azureADDeviceId = models.CharField(max_length = 50, null=True)
    deviceRegistrationState = models.CharField(max_length = 50, null=True)
    deviceCategoryDisplayName = models.CharField(max_length = 50, null=True)
    isSupervised = models.BooleanField(null=True)
    exchangeLastSuccessfulSyncDateTime = models.DateTimeField(null=True)
    exchangeAccessState = models.CharField(max_length = 50, null=True)
    exchangeAccessStateReason = models.CharField(max_length = 50, null=True)
    remoteAssistanceSessionUrl = models.CharField(max_length = 50, null=True)
    remoteAssistanceSessionErrorDetails = models.CharField(max_length = 50, null=True)
    isEncrypted = models.BooleanField(null=True)
    userPrincipalName = models.CharField(max_length = 50, null=True)
    model = models.CharField(max_length = 50, null=True)
    manufacturer = models.CharField(max_length = 50, null=True)
    imei = models.CharField(max_length = 50, null=True)
    complianceGracePeriodExpirationDateTime = models.DateTimeField(null=True)
    serialNumber = models.CharField(max_length = 50, null=True)
    phoneNumber = models.CharField(max_length = 50, null=True)
    androidSecurityPatchLevel = models.CharField(max_length = 50, null=True)
    userDisplayName = models.CharField(max_length = 100, null=True)
    configurationManagerClientEnabledFeatures = models.CharField(max_length = 50, null=True)
    wiFiMacAddress = models.CharField(max_length = 50, null=True)
    deviceHealthAttestationState = models.CharField(max_length = 50, null=True)
    subscriberCarrier = models.CharField(max_length = 50, null=True)
    meid = models.CharField(max_length = 50, null=True)
    totalStorageSpaceInBytes = models.CharField(max_length = 100, null=True)
    freeStorageSpaceInBytes = models.IntegerField(null=True)
    managedDeviceName = models.CharField(max_length = 200, null=True)
    partnerReportedThreatState = models.CharField(max_length = 50, null=True)
    requireUserEnrollmentApproval = models.CharField(max_length = 50, null=True)
    managementCertificateExpirationDate = models.DateTimeField(null=True)
    iccid = models.CharField(max_length = 50, null=True)
    udid = models.CharField(max_length = 50, null=True)
    notes = models.CharField(max_length = 500, null=True)
    ethernetMacAddress = models.CharField(max_length = 50, null=True)
    physicalMemoryInBytes = models.IntegerField(null=True)
    # deviceActionResults = models.CharField(max_length = 50)
    parentDevice = models.ForeignKey("Device", on_delete=models.CASCADE, null=True, related_name='integrationIntune')
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

    def __str__(self):
        return self.deviceName
    

class SophosDevice(models.Model):
    id = models.CharField(max_length = 100, primary_key=True)
    type = models.CharField(max_length = 50, null=True)
    hostname = models.CharField(max_length = 50, null=True)
    tenant_id = models.CharField(max_length = 100, null=True)
    os_isServer = models.BooleanField(null=True)
    os_platform = models.CharField(max_length = 50, null=True)
    os_name = models.CharField(max_length = 100, null=True)
    os_majorVersion = models.CharField(max_length = 100, null=True)
    os_minorVersion = models.CharField(max_length = 100, null=True)
    os_build = models.CharField(max_length = 100, null=True)
    ipv4Addresses = models.CharField(max_length = 50, null=True)
    macAddresses = models.CharField(max_length = 50, null=True)
    associatedPerson_viaLogin = models.CharField(max_length = 50, null=True)
    tamperProtectionEnabled = models.BooleanField(null=True)
    lastSeenAt = models.DateTimeField(null=True)
    lockdown_status = models.CharField(max_length = 50, null=True)
    lockdown_updateStatus = models.CharField(max_length = 50, null=True)
    isolation_status = models.CharField(max_length = 50, null=True)
    isolation_adminIsolated = models.BooleanField(null=True)
    isolation_selfIsolated = models.BooleanField(null=True)
    parentDevice = models.ForeignKey("Device", on_delete=models.CASCADE, null=True, related_name='integrationSophos')
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)
    
    def __str__(self):
        return self.hostname
