# Generated by Django 5.0.6 on 2024-06-08 18:50

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0079_device_compliant'),
    ]

    operations = [
        migrations.AddField(
            model_name='userdata',
            name='highest_authentication_strength',
            field=models.CharField(max_length=200, null=True),
        ),
        migrations.AddField(
            model_name='userdata',
            name='lowest_authentication_strength',
            field=models.CharField(max_length=200, null=True),
        ),
    ]
