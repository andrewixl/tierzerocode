from django.db import models

class Device(models.Model):
    hostname = models.CharField(max_length = 50, null=True)
    OS_PLATFORM_CHOICES = (
        ("Android", "Android"),
        ("Ubuntu", "Ubuntu"),
        ("Windows", "Windows"),
        ("Windows Server", "Windows Server"),
        ("Other", "Other"),
    )
    osPlatform = models.CharField(max_length = 20, choices=OS_PLATFORM_CHOICES, null=True)
    ENDPOINT_TYPE_CHOICES = (
        ("Client", "Client"),
        ("Server", "Server"),
        ("Mobile", "Mobile"),
        ("Other", "Other"),
    )
    endpointType = models.CharField(max_length=9, choices=ENDPOINT_TYPE_CHOICES, null=True)

    def __str__(self):
        return self.hostname
    
class Integration(models.Model):
    enabled = models.BooleanField(null=True, default=False)
    INTEGRATION_CHOICES = (
        ("CrowdStrike Falcon", "CrowdStrike Falcon"),
        ("Microsoft Defender for Endpoint", "Microsoft Defender for Endpoint"),
        ("Microsoft Entra ID", "Microsoft Entra ID"),
        ("Microsoft Intune", "Microsoft Intune"),
        ("Sophos Central", "Sophos Central"),
        ("Qualys", "Qualys"),  
    )
    integration_type = models.CharField(max_length=35, choices=INTEGRATION_CHOICES, null=True)
    image_navbar_path = models.CharField(max_length = 100, null=True)
    image_integration_path = models.CharField(max_length = 100, null=True)
    client_id = models.CharField(max_length = 100, null=True)
    client_secret = models.CharField(max_length = 200, null=True)
    tenant_id = models.CharField(max_length = 100, null=True)
    tenant_domain = models.CharField(max_length = 50, null=True)

    def __str__(self):
        return self.integration_type

class CrowdStrikeFalconDevice(models.Model):
    id = models.CharField(max_length = 100, primary_key=True)
    hostname = models.CharField(max_length = 100, null=True)
    osPlatform = models.CharField(max_length = 50, null=True)
    endpointType = models.CharField(max_length = 25, null=True)
    parentDevice = models.ForeignKey("Device", on_delete=models.CASCADE, null=True, related_name='integrationCrowdStrikeFalcon')
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

    def __str__(self):
        return self.hostname

class MicrosoftEntraIDDevice(models.Model):
    id = models.CharField(max_length = 100, primary_key=True)
    deviceId = models.CharField(max_length = 100, null=True)
    hostname = models.CharField(max_length = 100, null=True)
    osPlatform = models.CharField(max_length = 50, null=True)
    endpointType = models.CharField(max_length = 25, null=True)
    parentDevice = models.ForeignKey("Device", on_delete=models.CASCADE, null=True, related_name='integrationMicrosoftEntraID')
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

    def __str__(self):
        return self.hostname

class IntuneDevice(models.Model):
    id = models.CharField(max_length = 100, primary_key=True)
    userId = models.CharField(max_length = 50, null=True)
    hostname = models.CharField(max_length = 100, null=True)
    managedDeviceOwnerType = models.CharField(max_length = 25, null=True)
    enrolledDateTime = models.DateTimeField(null=True)
    lastSyncDateTime = models.DateTimeField(null=True)
    osPlatform = models.CharField(max_length = 25, null=True)
    endpointType = models.CharField(max_length = 25, null=True)
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
        return self.hostname
    

class SophosDevice(models.Model):
    id = models.CharField(max_length = 100, primary_key=True)
    type = models.CharField(max_length = 50, null=True)
    hostname = models.CharField(max_length = 50, null=True)
    tenant_id = models.CharField(max_length = 100, null=True)
    os_isServer = models.BooleanField(null=True)
    osPlatform = models.CharField(max_length = 50, null=True)
    endpointType = models.CharField(max_length = 25, null=True)
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

class DefenderDevice(models.Model):
    id = models.CharField(max_length = 100, primary_key=True)
    mergedIntoMachineId = models.CharField(max_length = 50, null=True)
    isPotentialDuplication = models.BooleanField(null=True)
    isExcluded = models.BooleanField(null=True)
    exclusionReason = models.CharField(max_length = 50, null=True)
    hostname = models.CharField(max_length = 100, null=True)
    firstSeen = models.CharField(max_length = 50, null=True)
    lastSeen = models.CharField(max_length = 50, null=True)
    osPlatform = models.CharField(max_length = 50, null=True)
    endpointType = models.CharField(max_length = 25, null=True)
    osVersion = models.CharField(max_length = 50, null=True)
    osProcessor = models.CharField(max_length = 50, null=True)
    version = models.CharField(max_length = 50, null=True)
    lastIpAddress = models.CharField(max_length = 50, null=True)
    lastExternalIpAddress = models.CharField(max_length = 50, null=True)
    agentVersion = models.CharField(max_length = 50, null=True)
    osBuild = models.IntegerField(null=True)
    healthStatus = models.CharField(max_length = 50, null=True)
    deviceValue = models.CharField(max_length = 50, null=True)
    rbacGroupId = models.IntegerField(null=True)
    rbacGroupName = models.CharField(max_length = 50, null=True)
    riskScore = models.CharField(max_length = 50, null=True)
    exposureLevel = models.CharField(max_length = 50, null=True)
    isAadJoined = models.BooleanField(null=True)
    aadDeviceId = models.CharField(max_length = 50, null=True)
    defenderAvStatus = models.CharField(max_length = 50, null=True)
    onboardingStatus = models.CharField(max_length = 50, null=True)
    osArchitecture = models.CharField(max_length = 50, null=True)
    managedBy = models.CharField(max_length = 50, null=True)
    managedByStatus = models.CharField(max_length = 50, null=True)
    vmMetadata = models.CharField(max_length = 50, null=True)
    parentDevice = models.ForeignKey("Device", on_delete=models.CASCADE, null=True, related_name='integrationDefender')
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

    def __str__(self):
        return self.hostname

class QualysDevice(models.Model):
    id = models.CharField(max_length = 100, primary_key=True)
    hostname = models.CharField(max_length = 100, null=True)
    osPlatform = models.CharField(max_length = 50, null=True)
    endpointType = models.CharField(max_length = 25, null=True)
    firstFoundDate = models.CharField(max_length = 50, null=True)
    ipAddress = models.CharField(max_length = 50, null=True)
    parentDevice = models.ForeignKey("Device", on_delete=models.CASCADE, null=True, related_name='integrationQualys')
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

    def __str__(self):
        return self.hostname