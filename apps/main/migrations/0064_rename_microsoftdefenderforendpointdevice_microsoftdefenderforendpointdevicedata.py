# Generated by Django 5.0.2 on 2024-05-25 03:44

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0063_microsoftdefenderforendpointdevice_and_more'),
    ]

    operations = [
        migrations.RenameModel(
            old_name='MicrosoftDefenderforEndpointDevice',
            new_name='MicrosoftDefenderforEndpointDeviceData',
        ),
    ]