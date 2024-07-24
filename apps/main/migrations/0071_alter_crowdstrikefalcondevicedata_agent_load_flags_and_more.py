# Generated by Django 5.0.6 on 2024-05-30 13:29

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0070_crowdstrikefalcondevicedata_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='crowdstrikefalcondevicedata',
            name='agent_load_flags',
            field=models.CharField(max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='crowdstrikefalcondevicedata',
            name='agent_version',
            field=models.CharField(max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='crowdstrikefalcondevicedata',
            name='base_image_version',
            field=models.CharField(max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='crowdstrikefalcondevicedata',
            name='bios_manufacturer',
            field=models.CharField(max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='crowdstrikefalcondevicedata',
            name='bios_version',
            field=models.CharField(max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='crowdstrikefalcondevicedata',
            name='build_number',
            field=models.CharField(max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='crowdstrikefalcondevicedata',
            name='chassis_type',
            field=models.CharField(max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='crowdstrikefalcondevicedata',
            name='chassis_type_desc',
            field=models.CharField(max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='crowdstrikefalcondevicedata',
            name='cid',
            field=models.CharField(max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='crowdstrikefalcondevicedata',
            name='config_id_base',
            field=models.CharField(max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='crowdstrikefalcondevicedata',
            name='config_id_build',
            field=models.CharField(max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='crowdstrikefalcondevicedata',
            name='config_id_platform',
            field=models.CharField(max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='crowdstrikefalcondevicedata',
            name='connection_ip',
            field=models.CharField(max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='crowdstrikefalcondevicedata',
            name='connection_mac_address',
            field=models.CharField(max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='crowdstrikefalcondevicedata',
            name='cpu_signature',
            field=models.CharField(max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='crowdstrikefalcondevicedata',
            name='cpu_vendor',
            field=models.CharField(max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='crowdstrikefalcondevicedata',
            name='default_gateway_ip',
            field=models.CharField(max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='crowdstrikefalcondevicedata',
            name='deployment_type',
            field=models.CharField(max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='crowdstrikefalcondevicedata',
            name='detection_suppression_status',
            field=models.CharField(max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='crowdstrikefalcondevicedata',
            name='external_ip',
            field=models.CharField(max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='crowdstrikefalcondevicedata',
            name='group_hash',
            field=models.CharField(max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='crowdstrikefalcondevicedata',
            name='host_hidden_status',
            field=models.CharField(max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='crowdstrikefalcondevicedata',
            name='host_utc_offset',
            field=models.CharField(max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='crowdstrikefalcondevicedata',
            name='hostname',
            field=models.CharField(max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='crowdstrikefalcondevicedata',
            name='instance_id',
            field=models.CharField(max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='crowdstrikefalcondevicedata',
            name='internet_exposure',
            field=models.CharField(max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='crowdstrikefalcondevicedata',
            name='k8s_cluster_git_version',
            field=models.CharField(max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='crowdstrikefalcondevicedata',
            name='k8s_cluster_id',
            field=models.CharField(max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='crowdstrikefalcondevicedata',
            name='k8s_cluster_version',
            field=models.CharField(max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='crowdstrikefalcondevicedata',
            name='kernel_version',
            field=models.CharField(max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='crowdstrikefalcondevicedata',
            name='last_login_uid',
            field=models.CharField(max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='crowdstrikefalcondevicedata',
            name='last_login_user',
            field=models.CharField(max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='crowdstrikefalcondevicedata',
            name='last_login_user_sid',
            field=models.CharField(max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='crowdstrikefalcondevicedata',
            name='linux_sensor_mode',
            field=models.CharField(max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='crowdstrikefalcondevicedata',
            name='local_ip',
            field=models.CharField(max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='crowdstrikefalcondevicedata',
            name='mac_address',
            field=models.CharField(max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='crowdstrikefalcondevicedata',
            name='machine_domain',
            field=models.CharField(max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='crowdstrikefalcondevicedata',
            name='major_version',
            field=models.CharField(max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='crowdstrikefalcondevicedata',
            name='minor_version',
            field=models.CharField(max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='crowdstrikefalcondevicedata',
            name='os_build',
            field=models.CharField(max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='crowdstrikefalcondevicedata',
            name='os_product_name',
            field=models.CharField(max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='crowdstrikefalcondevicedata',
            name='os_version',
            field=models.CharField(max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='crowdstrikefalcondevicedata',
            name='platform_id',
            field=models.CharField(max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='crowdstrikefalcondevicedata',
            name='platform_name',
            field=models.CharField(max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='crowdstrikefalcondevicedata',
            name='pod_host_ip4',
            field=models.CharField(max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='crowdstrikefalcondevicedata',
            name='pod_host_ip6',
            field=models.CharField(max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='crowdstrikefalcondevicedata',
            name='pod_hostname',
            field=models.CharField(max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='crowdstrikefalcondevicedata',
            name='pod_id',
            field=models.CharField(max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='crowdstrikefalcondevicedata',
            name='pod_ip4',
            field=models.CharField(max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='crowdstrikefalcondevicedata',
            name='pod_ip6',
            field=models.CharField(max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='crowdstrikefalcondevicedata',
            name='pod_name',
            field=models.CharField(max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='crowdstrikefalcondevicedata',
            name='pod_namespace',
            field=models.CharField(max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='crowdstrikefalcondevicedata',
            name='pod_service_account_name',
            field=models.CharField(max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='crowdstrikefalcondevicedata',
            name='pointer_size',
            field=models.CharField(max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='crowdstrikefalcondevicedata',
            name='product_type',
            field=models.CharField(max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='crowdstrikefalcondevicedata',
            name='product_type_desc',
            field=models.CharField(max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='crowdstrikefalcondevicedata',
            name='provision_status',
            field=models.CharField(max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='crowdstrikefalcondevicedata',
            name='reduced_functionality_mode',
            field=models.CharField(max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='crowdstrikefalcondevicedata',
            name='release_group',
            field=models.CharField(max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='crowdstrikefalcondevicedata',
            name='rtr_state',
            field=models.CharField(max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='crowdstrikefalcondevicedata',
            name='serial_number',
            field=models.CharField(max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='crowdstrikefalcondevicedata',
            name='service_pack_major',
            field=models.CharField(max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='crowdstrikefalcondevicedata',
            name='service_pack_minor',
            field=models.CharField(max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='crowdstrikefalcondevicedata',
            name='service_provider',
            field=models.CharField(max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='crowdstrikefalcondevicedata',
            name='service_provider_account_id',
            field=models.CharField(max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='crowdstrikefalcondevicedata',
            name='site_name',
            field=models.CharField(max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='crowdstrikefalcondevicedata',
            name='status',
            field=models.CharField(max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='crowdstrikefalcondevicedata',
            name='system_manufacturer',
            field=models.CharField(max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='crowdstrikefalcondevicedata',
            name='system_product_name',
            field=models.CharField(max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='crowdstrikefalcondevicedata',
            name='zone_group',
            field=models.CharField(max_length=100, null=True),
        ),
    ]