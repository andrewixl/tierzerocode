# Generated by Django 5.0.2 on 2024-05-31 20:59

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0073_alter_cloudflarezerotrustdevice_osplatform_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='microsoftdefenderforendpointdevicedata',
            name='osBuild',
            field=models.BigIntegerField(null=True),
        ),
        migrations.AlterField(
            model_name='microsoftdefenderforendpointdevicedata',
            name='rbacGroupId',
            field=models.BigIntegerField(null=True),
        ),
        migrations.AlterField(
            model_name='microsoftintunedevicedata',
            name='freeStorageSpaceInBytes',
            field=models.BigIntegerField(null=True),
        ),
        migrations.AlterField(
            model_name='microsoftintunedevicedata',
            name='physicalMemoryInBytes',
            field=models.BigIntegerField(null=True),
        ),
    ]