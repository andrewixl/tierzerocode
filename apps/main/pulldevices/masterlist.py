from ..models import Device, IntuneDevice, SophosDevice

def updateMasterList(devices):
    for device in devices:
        if device.parentDevice == None:
            if len(Device.objects.filter(hostname=device)) == 0:
                newDevice = Device.objects.create(hostname=device)
                device.parentDevice = newDevice
            else:
                device.parentDevice = Device.objects.get(hostname=device)
            device.save()
    return 'Success'