import os
import psutil

def get_removable_drives():
    removable = set()
    try:
        for part in psutil.disk_partitions(all=False):
            if 'removable' in part.opts or 'cdrom' in part.opts:
                removable.add(part.mountpoint)
    except Exception as e:
        print(f"Error getting drives: {e}")
    return removable

def get_all_usb_devices():
    devices = {}
    try:
        cmd = 'wmic path Win32_PnPEntity where "PNPDeviceID like \'USB%\'" get Name,PNPDeviceID'
        with os.popen(cmd) as pipe:
            lines = pipe.readlines()
            for line in lines[1:]:
                line = line.strip()
                if not line: continue
                parts = line.rsplit(None, 1)
                if len(parts) == 2:
                    name, pnp_id = parts
                    devices[pnp_id] = name
    except Exception as e:
        print(f"Error getting USB devices: {e}")
    return devices

print("Current Removable Drives:", get_removable_drives())
print("Current USB Devices:", get_all_usb_devices())
