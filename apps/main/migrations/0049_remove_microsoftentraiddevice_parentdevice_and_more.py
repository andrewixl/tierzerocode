# Generated by Django 5.0.2 on 2024-04-16 02:27

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0048_integration_integration_type_short'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='microsoftentraiddevice',
            name='parentDevice',
        ),
        migrations.CreateModel(
            name='MicrosoftEntraIDDeviceData',
            fields=[
                ('id', models.CharField(max_length=100, primary_key=True, serialize=False)),
                ('created_at', models.DateTimeField(auto_now_add=True, null=True)),
                ('updated_at', models.DateTimeField(auto_now=True, null=True)),
                ('parentDevice', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, related_name='integrationMicrosoftEntraID', to='main.device')),
            ],
        ),
        migrations.CreateModel(
            name='MicrosoftIntuneDeviceData',
            fields=[
                ('id', models.CharField(max_length=100, primary_key=True, serialize=False)),
                ('created_at', models.DateTimeField(auto_now_add=True, null=True)),
                ('updated_at', models.DateTimeField(auto_now=True, null=True)),
                ('parentDevice', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, related_name='integrationIntune', to='main.device')),
            ],
        ),
        migrations.DeleteModel(
            name='IntuneDevice',
        ),
        migrations.DeleteModel(
            name='MicrosoftEntraIDDevice',
        ),
    ]
