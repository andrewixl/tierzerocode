# Generated by Django 5.0.2 on 2024-03-29 03:44

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0044_devicecompliancesettings'),
    ]

    operations = [
        migrations.AddField(
            model_name='devicecompliancesettings',
            name='os_platform',
            field=models.CharField(max_length=100, null=True),
        ),
    ]