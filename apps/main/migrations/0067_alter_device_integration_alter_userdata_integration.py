# Generated by Django 5.0.2 on 2024-05-25 20:19

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0066_rename_excludereason_microsoftdefenderforendpointdevicedata_exclusionreason'),
    ]

    operations = [
        migrations.AlterField(
            model_name='device',
            name='integration',
            field=models.ManyToManyField(related_name='devices', to='main.integration'),
        ),
        migrations.AlterField(
            model_name='userdata',
            name='integration',
            field=models.ManyToManyField(related_name='users', to='main.integration'),
        ),
    ]