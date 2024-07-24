# Generated by Django 5.0.2 on 2024-06-01 02:03

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0075_device_manufacturer'),
    ]

    operations = [
        migrations.CreateModel(
            name='SophosCentralDeviceData',
            fields=[
                ('id', models.CharField(max_length=100, primary_key=True, serialize=False)),
                ('type', models.CharField(max_length=100, null=True)),
                ('hostname', models.CharField(max_length=75, null=True)),
                ('os_isServer', models.BooleanField(null=True)),
                ('os_platform', models.CharField(max_length=100, null=True)),
                ('os_name', models.CharField(max_length=100, null=True)),
                ('os_majorVersion', models.CharField(max_length=100, null=True)),
                ('os_minorVersion', models.CharField(max_length=100, null=True)),
                ('os_build', models.CharField(max_length=100, null=True)),
                ('associatedPerson_name', models.CharField(max_length=100, null=True)),
                ('associatedPerson_viaLogin', models.CharField(max_length=100, null=True)),
                ('associatedPerson_id', models.CharField(max_length=100, null=True)),
                ('tamperProtectionEnabled', models.BooleanField(null=True)),
                ('lastSeenAt', models.DateTimeField(null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True, null=True)),
                ('updated_at', models.DateTimeField(auto_now=True, null=True)),
                ('parentDevice', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, related_name='integrationSophos', to='main.device')),
            ],
        ),
        migrations.DeleteModel(
            name='SophosDevice',
        ),
    ]