from django.db import models

class Device(models.Model):
    hostname = models.CharField(max_length=75, null=True)
    compliant = models.BooleanField(null=False, default=False)
    OS_PLATFORM_CHOICES = (
        ("Android", "Android"),
        ("iOS/iPadOS", "iOS/iPadOS"),
        ("MacOS", "MacOS"),
        ("Red Hat Enterprise Linux", "Red Hat Enterprise Linux"),
        ("CentOS", "CentOS"),
        ("Ubuntu", "Ubuntu"),
        ("Windows", "Windows"),
        ("Windows Server", "Windows Server"),
        ("Other", "Other"),
    )
    osPlatform = models.CharField(max_length=25, choices=OS_PLATFORM_CHOICES, null=True)
    ENDPOINT_TYPE_CHOICES = (
        ("Client", "Client"),
        ("Server", "Server"),
        ("Mobile", "Mobile"),
        ("Other", "Other"),
    )
    endpointType = models.CharField(max_length=9, choices=ENDPOINT_TYPE_CHOICES, null=True)
    manufacturer = models.CharField(max_length=200, null=True)
    integration = models.ManyToManyField("Integration", related_name='devices')
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

    def __str__(self):
        return self.hostname

class DeviceComplianceSettings(models.Model):
    os_platform = models.CharField(max_length=200, null=True)
    cloudflare_zero_trust = models.BooleanField(null=True)
    crowdstrike_falcon = models.BooleanField(null=True)
    microsoft_defender_for_endpoint = models.BooleanField(null=True)
    microsoft_entra_id = models.BooleanField(null=True)
    microsoft_intune = models.BooleanField(null=True)
    sophos_central = models.BooleanField(null=True)
    qualys = models.BooleanField(null=True)
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

    def __str__(self):
        return self.os_platform
    
class Integration(models.Model):
    enabled = models.BooleanField(null=True, default=False)
    INTEGRATION_CHOICES = (
        ("Cloudflare Zero Trust", "Cloudflare Zero Trust"),
        ("CrowdStrike Falcon", "CrowdStrike Falcon"),
        ("Microsoft Defender for Endpoint", "Microsoft Defender for Endpoint"),
        ("Microsoft Entra ID", "Microsoft Entra ID"),
        ("Microsoft Intune", "Microsoft Intune"),
        ("Sophos Central", "Sophos Central"),
        ("Qualys", "Qualys"),  
    )
    integration_type = models.CharField(max_length=35, choices=INTEGRATION_CHOICES, null=True)
    integration_type_short = models.CharField(max_length=35, null=True)
    INTEGRATION_CONTEXTS = (
        ("Cloud Configuration", "Cloud Configuration"),
        ("Device", "Device"),
        ("User", "User"),
    )
    integration_context = models.CharField(max_length=35, choices=INTEGRATION_CONTEXTS, null=True)
    image_navbar_path = models.CharField(max_length=200, null=True)
    image_integration_path = models.CharField(max_length=200, null=True)
    client_id = models.CharField(max_length=200, null=True)
    client_secret = models.CharField(max_length=200, null=True)
    tenant_id = models.CharField(max_length=200, null=True)
    tenant_domain = models.CharField(max_length=200, null=True)
    last_synced_at = models.DateTimeField(null=True)
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

    def __str__(self):
        return self.integration_type 

class CloudflareZeroTrustDevice(models.Model):
    id = models.CharField(max_length=200, primary_key=True)
    hostname = models.CharField(max_length=200, null=True)
    osPlatform = models.CharField(max_length=200, null=True)
    endpointType = models.CharField(max_length=25, null=True)
    parentDevice = models.ForeignKey("Device", on_delete=models.CASCADE, null=True, related_name='integrationCloudflareZeroTrust')
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

    def __str__(self):
        return self.hostname

class CrowdStrikeFalconDeviceData(models.Model):
    id = models.CharField(max_length=200, primary_key=True)
    agent_load_flags = models.CharField(max_length=200, null=True)
    agent_local_time = models.DateTimeField(null=True)
    agent_version = models.CharField(max_length=200, null=True)
    base_image_version = models.CharField(max_length=200, null=True)
    bios_manufacturer = models.CharField(max_length=200, null=True)
    bios_version = models.CharField(max_length=200, null=True)
    build_number = models.CharField(max_length=200, null=True)
    chassis_type = models.CharField(max_length=200, null=True)
    chassis_type_desc = models.CharField(max_length=200, null=True)
    cid = models.CharField(max_length=200, null=True)
    config_id_base = models.CharField(max_length=200, null=True)
    config_id_build = models.CharField(max_length=200, null=True)
    config_id_platform = models.CharField(max_length=200, null=True)
    connection_ip = models.CharField(max_length=200, null=True)
    connection_mac_address = models.CharField(max_length=200, null=True)
    cpu_signature = models.CharField(max_length=200, null=True)
    cpu_vendor = models.CharField(max_length=200, null=True)
    default_gateway_ip = models.CharField(max_length=200, null=True)
    deployment_type = models.CharField(max_length=200, null=True)
    detection_suppression_status = models.CharField(max_length=200, null=True)
    email = models.EmailField(max_length=200, null=True)
    external_ip = models.CharField(max_length=200, null=True)
    first_login_timestamp = models.DateTimeField(null=True)
    first_seen = models.DateTimeField(null=True)
    group_hash = models.CharField(max_length=200, null=True)
    host_hidden_status = models.CharField(max_length=200, null=True)
    host_utc_offset = models.CharField(max_length=200, null=True)
    hostname = models.CharField(max_length=200, null=True)
    instance_id = models.CharField(max_length=200, null=True)
    internet_exposure = models.CharField(max_length=200, null=True)
    k8s_cluster_git_version = models.CharField(max_length=200, null=True)
    k8s_cluster_id = models.CharField(max_length=200, null=True)
    k8s_cluster_version = models.CharField(max_length=200, null=True)
    kernel_version = models.CharField(max_length=200, null=True)
    last_login_timestamp = models.DateTimeField(null=True)
    last_login_uid = models.CharField(max_length=200, null=True)
    last_login_user = models.CharField(max_length=200, null=True)
    last_login_user_sid = models.CharField(max_length=200, null=True)
    last_reboot = models.DateTimeField(null=True)
    last_seen = models.DateTimeField(null=True)
    linux_sensor_mode = models.CharField(max_length=200, null=True)
    local_ip = models.CharField(max_length=200, null=True)
    mac_address = models.CharField(max_length=200, null=True)
    machine_domain = models.CharField(max_length=200, null=True)
    major_version = models.CharField(max_length=200, null=True)
    migration_completed_time = models.DateTimeField(null=True)
    minor_version = models.CharField(max_length=200, null=True)
    modified_timestamp = models.DateTimeField(null=True)
    os_build = models.CharField(max_length=200, null=True)
    os_product_name = models.CharField(max_length=200, null=True)
    os_version = models.CharField(max_length=200, null=True)
    platform_id = models.CharField(max_length=200, null=True)
    platform_name = models.CharField(max_length=200, null=True)
    pod_host_ip4 = models.CharField(max_length=200, null=True)
    pod_host_ip6 = models.CharField(max_length=200, null=True)
    pod_hostname = models.CharField(max_length=200, null=True)
    pod_id = models.CharField(max_length=200, null=True)
    pod_ip4 = models.CharField(max_length=200, null=True)
    pod_ip6 = models.CharField(max_length=200, null=True)
    pod_name = models.CharField(max_length=200, null=True)
    pod_namespace = models.CharField(max_length=200, null=True)
    pod_service_account_name = models.CharField(max_length=200, null=True)
    pointer_size = models.CharField(max_length=200, null=True)
    product_type = models.CharField(max_length=200, null=True)
    product_type_desc = models.CharField(max_length=200, null=True)
    provision_status = models.CharField(max_length=200, null=True)
    reduced_functionality_mode = models.CharField(max_length=200, null=True)
    release_group = models.CharField(max_length=200, null=True)
    rtr_state = models.CharField(max_length=200, null=True)
    serial_number = models.CharField(max_length=200, null=True)
    service_pack_major = models.CharField(max_length=200, null=True)
    service_pack_minor = models.CharField(max_length=200, null=True)
    service_provider = models.CharField(max_length=200, null=True)
    service_provider_account_id = models.CharField(max_length=200, null=True)
    site_name = models.CharField(max_length=200, null=True)
    status = models.CharField(max_length=200, null=True)
    system_manufacturer = models.CharField(max_length=200, null=True)
    system_product_name = models.CharField(max_length=200, null=True)
    zone_group = models.CharField(max_length=200, null=True)
    parentDevice = models.ForeignKey("Device", on_delete=models.CASCADE, null=True, related_name='integrationCrowdStrikeFalcon')
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

    def __str__(self):
        return self.hostname

class MicrosoftEntraIDDeviceData(models.Model):
    id = models.CharField(max_length=200, primary_key=True)
    deletedDateTime = models.DateTimeField(null=True)
    accountEnabled = models.BooleanField(null=True)
    approximateLastSignInDateTime = models.DateTimeField(null=True)
    complianceExpirationDateTime = models.DateTimeField(null=True)
    createdDateTime = models.DateTimeField(null=True)
    deviceCategory = models.CharField(max_length=200, null=True)
    deviceId = models.CharField(max_length=200, null=True)
    deviceMetadata = models.CharField(max_length=200, null=True)
    deviceOwnership = models.CharField(max_length=200, null=True)
    deviceVersion = models.CharField(max_length=200, null=True)
    displayName = models.CharField(max_length=200, null=True)
    domainName = models.CharField(max_length=75, null=True)
    enrollmentProfileName = models.CharField(max_length=200, null=True)
    enrollmentType = models.CharField(max_length=200, null=True)
    externalSourceName = models.CharField(max_length=200, null=True)
    isCompliant = models.BooleanField(null=True)
    isManaged = models.BooleanField(null=True)
    isRooted = models.BooleanField(null=True)
    managementType = models.CharField(max_length=200, null=True)
    manufacturer = models.CharField(max_length=200, null=True)
    mdmAppId = models.CharField(max_length=200, null=True)
    model = models.CharField(max_length=200, null=True)
    onPremisesLastSyncDateTime = models.DateTimeField(null=True)
    onPremisesSyncEnabled = models.BooleanField(null=True)
    operatingSystem = models.CharField(max_length=200, null=True)
    operatingSystemVersion = models.CharField(max_length=200, null=True)
    profileType = models.CharField(max_length=200, null=True)
    registrationDateTime = models.DateTimeField(null=True)
    sourceType = models.CharField(max_length=200, null=True)
    trustType = models.CharField(max_length=200, null=True)
    parentDevice = models.ForeignKey("Device", on_delete=models.CASCADE, null=True, related_name='integrationMicrosoftEntraID')
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

    def __str__(self):
        return self.displayName 

class MicrosoftIntuneDeviceData(models.Model):
    id = models.CharField(max_length=200, primary_key=True)
    userId = models.CharField(max_length=200, null=True)
    deviceName = models.CharField(max_length=200, null=True)
    managedDeviceOwnerType = models.CharField(max_length=25, null=True)
    enrolledDateTime = models.DateTimeField(null=True)
    lastSyncDateTime = models.DateTimeField(null=True)
    operatingSystem = models.CharField(max_length=25, null=True)
    complianceState = models.CharField(max_length=25, null=True)
    jailBroken = models.CharField(max_length=25, null=True)
    managementAgent = models.CharField(max_length=200, null=True)
    osVersion = models.CharField(max_length=25, null=True)
    easActivated = models.BooleanField(null=True)
    easDeviceId = models.CharField(max_length=200, null=True)
    easActivationDateTime = models.DateTimeField(null=True)
    azureADRegistered = models.BooleanField(null=True)
    deviceEnrollmentType = models.CharField(max_length=200, null=True)
    activationLockBypassCode = models.CharField(max_length=200, null=True)
    emailAddress = models.EmailField(max_length=200, null=True)
    azureADDeviceId = models.CharField(max_length=200, null=True)
    deviceRegistrationState = models.CharField(max_length=200, null=True)
    deviceCategoryDisplayName = models.CharField(max_length=200, null=True)
    isSupervised = models.BooleanField(null=True)
    exchangeLastSuccessfulSyncDateTime = models.DateTimeField(null=True)
    exchangeAccessState = models.CharField(max_length=200, null=True)
    exchangeAccessStateReason = models.CharField(max_length=200, null=True)
    remoteAssistanceSessionUrl = models.CharField(max_length=200, null=True)
    remoteAssistanceSessionErrorDetails = models.CharField(max_length=200, null=True)
    isEncrypted = models.BooleanField(null=True)
    userPrincipalName = models.CharField(max_length=200, null=True)
    model = models.CharField(max_length=200, null=True)
    manufacturer = models.CharField(max_length=200, null=True)
    imei = models.CharField(max_length=200, null=True)
    complianceGracePeriodExpirationDateTime = models.DateTimeField(null=True)
    serialNumber = models.CharField(max_length=200, null=True)
    phoneNumber = models.CharField(max_length=200, null=True)
    androidSecurityPatchLevel = models.CharField(max_length=200, null=True)
    userDisplayName = models.CharField(max_length=200, null=True)
    configurationManagerClientEnabledFeatures = models.CharField(max_length=200, null=True)
    wiFiMacAddress = models.CharField(max_length=200, null=True)
    deviceHealthAttestationState = models.CharField(max_length=200, null=True)
    subscriberCarrier = models.CharField(max_length=200, null=True)
    meid = models.CharField(max_length=200, null=True)
    totalStorageSpaceInBytes = models.CharField(max_length=200, null=True)
    freeStorageSpaceInBytes = models.BigIntegerField(null=True)
    managedDeviceName = models.CharField(max_length=200, null=True)
    partnerReportedThreatState = models.CharField(max_length=200, null=True)
    requireUserEnrollmentApproval = models.CharField(max_length=200, null=True)
    managementCertificateExpirationDate = models.DateTimeField(null=True)
    iccid = models.CharField(max_length=200, null=True)
    udid = models.CharField(max_length=200, null=True)
    notes = models.CharField(max_length=200, null=True)
    ethernetMacAddress = models.CharField(max_length=200, null=True)
    physicalMemoryInBytes = models.BigIntegerField(null=True)
    enrollmentProfileName = models.CharField(max_length=200, null=True)
    parentDevice = models.ForeignKey("Device", on_delete=models.CASCADE, null=True, related_name='integrationIntune')
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

    def __str__(self):
        return self.deviceName
    

class SophosCentralDeviceData(models.Model):
    id = models.CharField(max_length=200, primary_key=True)
    type = models.CharField(max_length=200, null=True)
    hostname = models.CharField(max_length=75, null=True)
    os_isServer = models.BooleanField(null=True)
    os_platform = models.CharField(max_length=200, null=True)
    os_name = models.CharField(max_length=200, null=True)
    os_majorVersion = models.CharField(max_length=200, null=True)
    os_minorVersion = models.CharField(max_length=200, null=True)
    os_build = models.CharField(max_length=200, null=True)
    associatedPerson_name = models.CharField(max_length=200, null=True)
    associatedPerson_viaLogin = models.CharField(max_length=200, null=True)
    associatedPerson_id = models.CharField(max_length=200, null=True)
    tamperProtectionEnabled = models.BooleanField(null=True)
    lastSeenAt = models.DateTimeField(null=True)
    parentDevice = models.ForeignKey("Device", on_delete=models.CASCADE, null=True, related_name='integrationSophos')
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

    def __str__(self):
        return self.hostname

class MicrosoftDefenderforEndpointDeviceData(models.Model):
    id = models.CharField(max_length=200, primary_key=True)
    mergedIntoMachineId = models.CharField(max_length=200, null=True)
    isPotentialDuplication = models.BooleanField(null=True)
    isExcluded = models.BooleanField(null=True)
    exclusionReason = models.CharField(max_length=200, null=True)
    computerDnsName = models.CharField(max_length=200, null=True)
    firstSeen = models.CharField(max_length=200, null=True)
    lastSeen = models.CharField(max_length=200, null=True)
    osPlatform = models.CharField(max_length=200, null=True)
    osVersion = models.CharField(max_length=200, null=True)
    osProcessor = models.CharField(max_length=200, null=True)
    version = models.CharField(max_length=200, null=True)
    lastIpAddress = models.CharField(max_length=200, null=True)
    lastExternalIpAddress = models.CharField(max_length=200, null=True)
    agentVersion = models.CharField(max_length=200, null=True)
    osBuild = models.BigIntegerField(null=True)
    healthStatus = models.CharField(max_length=200, null=True)
    deviceValue = models.CharField(max_length=200, null=True)
    rbacGroupId = models.BigIntegerField(null=True)
    rbacGroupName = models.CharField(max_length=200, null=True)
    riskScore = models.CharField(max_length=200, null=True)
    exposureLevel = models.CharField(max_length=200, null=True)
    isAadJoined = models.BooleanField(null=True)
    aadDeviceId = models.CharField(max_length=200, null=True)
    defenderAvStatus = models.CharField(max_length=200, null=True)
    onboardingStatus = models.CharField(max_length=200, null=True)
    osArchitecture = models.CharField(max_length=200, null=True)
    managedBy = models.CharField(max_length=200, null=True)
    managedByStatus = models.CharField(max_length=200, null=True)
    vmMetadata = models.CharField(max_length=200, null=True)
    parentDevice = models.ForeignKey("Device", on_delete=models.CASCADE, null=True, related_name='integrationMicrosoftDefenderForEndpoint')
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

    def __str__(self):
        return self.computerDnsName

class QualysDevice(models.Model):
    id = models.CharField(max_length=200, primary_key=True)
    hostname = models.CharField(max_length=200, null=True)
    osPlatform = models.CharField(max_length=200, null=True)
    endpointType = models.CharField(max_length=25, null=True)
    firstFoundDate = models.CharField(max_length=200, null=True)
    ipAddress = models.CharField(max_length=200, null=True)
    parentDevice = models.ForeignKey("Device", on_delete=models.CASCADE, null=True, related_name='integrationQualys')
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

    def __str__(self):
        return self.hostname
    
class UserData(models.Model):
    upn = models.EmailField(max_length=200, null=True)
    uid = models.CharField(max_length=200, null=True)
    given_name = models.CharField(max_length=200, null=True)
    surname = models.CharField(max_length=200, null=True)
    highest_authentication_strength = models.CharField(max_length=200, null=True)
    lowest_authentication_strength = models.CharField(max_length=200, null=True)
    email_authentication_method = models.BooleanField(null=True)
    fido2_authentication_method = models.BooleanField(null=True)
    microsoft_authenticator_authentication_method = models.BooleanField(null=True)
    password_authentication_method = models.BooleanField(null=True)
    phone_authentication_method = models.BooleanField(null=True)
    software_oath_authentication_method = models.BooleanField(null=True)
    temporary_access_pass_authentication_method = models.BooleanField(null=True)
    windows_hello_for_business_authentication_method = models.BooleanField(null=True)
    integration = models.ManyToManyField("Integration", related_name='users')
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

    def __str__(self):
        return self.upn
