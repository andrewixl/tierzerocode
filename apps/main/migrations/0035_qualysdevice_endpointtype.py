# Generated by Django 5.0.2 on 2024-03-25 00:49

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0034_qualysdevice'),
    ]

    operations = [
        migrations.AddField(
            model_name='qualysdevice',
            name='endpointType',
            field=models.CharField(max_length=25, null=True),
        ),
    ]