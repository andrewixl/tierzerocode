from django.db import models

class SSOIntegration(models.Model):
    enabled = models.BooleanField(null=True, default=False)
    INTEGRATION_CHOICES = (
        ("Microsoft Entra ID", "Microsoft Entra ID"),
    )
    integration_type = models.CharField(max_length=35, choices=INTEGRATION_CHOICES, null=True)
    integration_type_short = models.CharField(max_length=35, null=True)
    image_navbar_path = models.CharField(max_length = 100, null=True)
    image_integration_path = models.CharField(max_length = 100, null=True)
    client_id = models.CharField(max_length = 100, null=True)
    client_secret = models.CharField(max_length = 200, null=True)
    tenant_id = models.CharField(max_length = 100, null=True)
    tenant_domain = models.CharField(max_length = 50, null=True)
    last_synced_at = models.DateTimeField(null=True)
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

    def __str__(self):
        return self.integration_type