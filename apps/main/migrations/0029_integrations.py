# Generated by Django 5.0.2 on 2024-03-21 16:07

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0028_defenderdevice_endpointtype_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='Integrations',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('enabled', models.BooleanField(default=False, null=True)),
                ('IntegrationType', models.CharField(choices=[('Microsoft Intune', 'Microsoft Intune'), ('Sophos Central', 'Sophos Central'), ('Microsoft Defender for Endpoint', 'Microsoft Defender for Endpoint'), ('CrowdStrike Falcon', 'CrowdStrike Falcon'), ('SCCM', 'SCCM'), ('Qualys', 'Qualys')], max_length=31, null=True)),
                ('client_id', models.CharField(max_length=50, null=True)),
                ('client_secret', models.CharField(max_length=50, null=True)),
                ('tenant_id', models.CharField(max_length=50, null=True)),
                ('tenant_domain', models.CharField(max_length=50, null=True)),
            ],
        ),
    ]