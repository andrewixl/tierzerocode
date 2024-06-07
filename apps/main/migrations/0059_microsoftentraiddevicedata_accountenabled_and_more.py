# Generated by Django 5.0.2 on 2024-05-25 00:22

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0058_microsoftintunedevicedata_enrollmentprofilename'),
    ]

    operations = [
        migrations.AddField(
            model_name='microsoftentraiddevicedata',
            name='accountEnabled',
            field=models.BooleanField(null=True),
        ),
        migrations.AddField(
            model_name='microsoftentraiddevicedata',
            name='approximateLastSignInDateTime',
            field=models.DateTimeField(null=True),
        ),
        migrations.AddField(
            model_name='microsoftentraiddevicedata',
            name='complianceExpirationDateTime',
            field=models.DateTimeField(null=True),
        ),
        migrations.AddField(
            model_name='microsoftentraiddevicedata',
            name='createdDateTime',
            field=models.DateTimeField(null=True),
        ),
        migrations.AddField(
            model_name='microsoftentraiddevicedata',
            name='deivceMetadata',
            field=models.CharField(max_length=50, null=True),
        ),
        migrations.AddField(
            model_name='microsoftentraiddevicedata',
            name='deletedDateTime',
            field=models.DateTimeField(null=True),
        ),
        migrations.AddField(
            model_name='microsoftentraiddevicedata',
            name='deviceCategory',
            field=models.CharField(max_length=50, null=True),
        ),
        migrations.AddField(
            model_name='microsoftentraiddevicedata',
            name='deviceId',
            field=models.CharField(max_length=50, null=True),
        ),
        migrations.AddField(
            model_name='microsoftentraiddevicedata',
            name='deviceOwnership',
            field=models.CharField(max_length=50, null=True),
        ),
        migrations.AddField(
            model_name='microsoftentraiddevicedata',
            name='deviceVersion',
            field=models.CharField(max_length=50, null=True),
        ),
        migrations.AddField(
            model_name='microsoftentraiddevicedata',
            name='displayName',
            field=models.CharField(max_length=50, null=True),
        ),
        migrations.AddField(
            model_name='microsoftentraiddevicedata',
            name='domainName',
            field=models.CharField(max_length=50, null=True),
        ),
        migrations.AddField(
            model_name='microsoftentraiddevicedata',
            name='enrollmentProfileName',
            field=models.CharField(max_length=50, null=True),
        ),
        migrations.AddField(
            model_name='microsoftentraiddevicedata',
            name='enrollmentType',
            field=models.CharField(max_length=50, null=True),
        ),
        migrations.AddField(
            model_name='microsoftentraiddevicedata',
            name='externalSourceName',
            field=models.CharField(max_length=50, null=True),
        ),
        migrations.AddField(
            model_name='microsoftentraiddevicedata',
            name='isCompliant',
            field=models.BooleanField(null=True),
        ),
        migrations.AddField(
            model_name='microsoftentraiddevicedata',
            name='isManaged',
            field=models.BooleanField(null=True),
        ),
        migrations.AddField(
            model_name='microsoftentraiddevicedata',
            name='isRooted',
            field=models.BooleanField(null=True),
        ),
        migrations.AddField(
            model_name='microsoftentraiddevicedata',
            name='managementType',
            field=models.CharField(max_length=50, null=True),
        ),
        migrations.AddField(
            model_name='microsoftentraiddevicedata',
            name='manufacturer',
            field=models.CharField(max_length=50, null=True),
        ),
        migrations.AddField(
            model_name='microsoftentraiddevicedata',
            name='mdmAppId',
            field=models.CharField(max_length=50, null=True),
        ),
        migrations.AddField(
            model_name='microsoftentraiddevicedata',
            name='model',
            field=models.CharField(max_length=50, null=True),
        ),
        migrations.AddField(
            model_name='microsoftentraiddevicedata',
            name='onPremisesLastSyncDateTime',
            field=models.DateTimeField(null=True),
        ),
        migrations.AddField(
            model_name='microsoftentraiddevicedata',
            name='onPremisesSyncEnabled',
            field=models.BooleanField(null=True),
        ),
        migrations.AddField(
            model_name='microsoftentraiddevicedata',
            name='operatingSystem',
            field=models.CharField(max_length=50, null=True),
        ),
        migrations.AddField(
            model_name='microsoftentraiddevicedata',
            name='operatingSystemVersion',
            field=models.CharField(max_length=50, null=True),
        ),
        migrations.AddField(
            model_name='microsoftentraiddevicedata',
            name='physicalIds_GID',
            field=models.CharField(max_length=50, null=True),
        ),
        migrations.AddField(
            model_name='microsoftentraiddevicedata',
            name='physicalIds_HWID',
            field=models.CharField(max_length=50, null=True),
        ),
        migrations.AddField(
            model_name='microsoftentraiddevicedata',
            name='physicalIds_ZTDID',
            field=models.CharField(max_length=50, null=True),
        ),
        migrations.AddField(
            model_name='microsoftentraiddevicedata',
            name='profileType',
            field=models.CharField(max_length=50, null=True),
        ),
        migrations.AddField(
            model_name='microsoftentraiddevicedata',
            name='registrationDateTime',
            field=models.DateTimeField(null=True),
        ),
        migrations.AddField(
            model_name='microsoftentraiddevicedata',
            name='sourceType',
            field=models.CharField(max_length=50, null=True),
        ),
        migrations.AddField(
            model_name='microsoftentraiddevicedata',
            name='trustType',
            field=models.CharField(max_length=50, null=True),
        ),
    ]