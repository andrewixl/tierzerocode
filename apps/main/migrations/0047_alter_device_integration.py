# Generated by Django 5.0.2 on 2024-03-30 02:34

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0046_device_created_at_device_integration_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='device',
            name='integration',
            field=models.ManyToManyField(null=True, related_name='devices', to='main.integration'),
        ),
    ]
