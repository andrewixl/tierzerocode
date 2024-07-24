# Generated by Django 5.0.2 on 2024-02-20 16:25

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0023_alter_device_endpointtype_alter_device_osplatform'),
    ]

    operations = [
        migrations.CreateModel(
            name='CrowdStrikeIntegration',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('enabled', models.BooleanField(default=False, null=True)),
                ('client_id', models.CharField(max_length=50, null=True)),
                ('client_secret', models.CharField(max_length=50, null=True)),
                ('tenant_id', models.CharField(max_length=50, null=True)),
                ('tenant_domain', models.CharField(max_length=50, null=True)),
            ],
        ),
    ]
