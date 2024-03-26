# Generated by Django 5.0.2 on 2024-03-25 22:29

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0038_remove_integration_image_integration_page_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='integration',
            name='integration_type',
            field=models.CharField(choices=[('CrowdStrike Falcon', 'CrowdStrike Falcon'), ('Microsoft Defender for Endpoint', 'Microsoft Defender for Endpoint'), ('Microsoft Entra ID', 'Microsoft Entra ID'), ('Microsoft Intune', 'Microsoft Intune'), ('Sophos Central', 'Sophos Central'), ('Qualys', 'Qualys')], max_length=35, null=True),
        ),
        migrations.CreateModel(
            name='CrowdStrikeFalconDevice',
            fields=[
                ('id', models.CharField(max_length=100, primary_key=True, serialize=False)),
                ('hostname', models.CharField(max_length=100, null=True)),
                ('osPlatform', models.CharField(max_length=50, null=True)),
                ('endpointType', models.CharField(max_length=25, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True, null=True)),
                ('updated_at', models.DateTimeField(auto_now=True, null=True)),
                ('parentDevice', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, related_name='integrationCrowdStrikeFalcon', to='main.device')),
            ],
        ),
        migrations.CreateModel(
            name='MicrosoftEntraIDDevice',
            fields=[
                ('id', models.CharField(max_length=100, primary_key=True, serialize=False)),
                ('hostname', models.CharField(max_length=100, null=True)),
                ('osPlatform', models.CharField(max_length=50, null=True)),
                ('endpointType', models.CharField(max_length=25, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True, null=True)),
                ('updated_at', models.DateTimeField(auto_now=True, null=True)),
                ('parentDevice', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, related_name='integrationMicrosoftEntraID', to='main.device')),
            ],
        ),
    ]