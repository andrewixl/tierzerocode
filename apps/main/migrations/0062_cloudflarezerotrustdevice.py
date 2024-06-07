# Generated by Django 5.0.2 on 2024-05-25 02:17

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0061_rename_deivcemetadata_microsoftentraiddevicedata_devicemetadata'),
    ]

    operations = [
        migrations.CreateModel(
            name='CloudflareZeroTrustDevice',
            fields=[
                ('id', models.CharField(max_length=100, primary_key=True, serialize=False)),
                ('hostname', models.CharField(max_length=100, null=True)),
                ('osPlatform', models.CharField(max_length=50, null=True)),
                ('endpointType', models.CharField(max_length=25, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True, null=True)),
                ('updated_at', models.DateTimeField(auto_now=True, null=True)),
                ('parentDevice', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, related_name='integrationCloudflareZeroTrust', to='main.device')),
            ],
        ),
    ]