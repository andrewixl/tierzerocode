# Generated by Django 5.0.2 on 2024-05-29 03:12

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('login_app', '0003_alter_user_permission'),
    ]

    operations = [
        migrations.CreateModel(
            name='SSOIntegration',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('enabled', models.BooleanField(default=False, null=True)),
                ('integration_type', models.CharField(choices=[('Microsoft Entra ID', 'Microsoft Entra ID')], max_length=35, null=True)),
                ('integration_type_short', models.CharField(max_length=35, null=True)),
                ('image_navbar_path', models.CharField(max_length=100, null=True)),
                ('image_integration_path', models.CharField(max_length=100, null=True)),
                ('client_id', models.CharField(max_length=100, null=True)),
                ('client_secret', models.CharField(max_length=200, null=True)),
                ('tenant_id', models.CharField(max_length=100, null=True)),
                ('tenant_domain', models.CharField(max_length=50, null=True)),
                ('last_synced_at', models.DateTimeField(null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True, null=True)),
                ('updated_at', models.DateTimeField(auto_now=True, null=True)),
            ],
        ),
        migrations.DeleteModel(
            name='User',
        ),
    ]
