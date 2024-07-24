# Generated by Django 5.0.2 on 2024-02-18 18:34

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0005_alter_intuneintegration_client_id_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='intuneintegration',
            name='client_id',
            field=models.CharField(max_length=50, null=True),
        ),
        migrations.AlterField(
            model_name='intuneintegration',
            name='client_secret',
            field=models.CharField(max_length=50, null=True),
        ),
        migrations.AlterField(
            model_name='intuneintegration',
            name='tenant_id',
            field=models.CharField(max_length=50, null=True),
        ),
        migrations.AlterField(
            model_name='sophosintegration',
            name='client_id',
            field=models.CharField(max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='sophosintegration',
            name='client_secret',
            field=models.CharField(max_length=200, null=True),
        ),
        migrations.AlterField(
            model_name='sophosintegration',
            name='tenant_id',
            field=models.CharField(max_length=100, null=True),
        ),
    ]
