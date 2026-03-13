import os
import time
import psutil
from datetime import datetime
import json

def get_timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def get_removable_drives():
    removable = set()
    try:
        for part in psutil.disk_partitions(all=False):
            if 'removable' in part.opts or 'cdrom' in part.opts:
                removable.add(part.mountpoint)
    except:
        pass
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
    except:
        pass
    return devices

def run_monitor():
    print("="*60)
    print(" USB CONSOLE ADMIN MONITOR - Real-time USB Tracking")
    print("="*60)
    print(f"[{get_timestamp()}] Initializing hardware monitor...")
    
    last_drives = get_removable_drives()
    last_usb_devices = get_all_usb_devices()
    
    print(f"[{get_timestamp()}] Currently connected USB devices: {len(last_usb_devices)}")
    for pnp_id, name in last_usb_devices.items():
        print(f" - {name}")
    
    print("\n[INFO] Monitoring for changes... (Press Ctrl+C to stop)")
    
    try:
        while True:
            # Check for drives
            current_drives = get_removable_drives()
            added_drives = current_drives - last_drives
            removed_drives = last_drives - current_drives

            for drive in added_drives:
                print(f"[{get_timestamp()}] \033[92m>>> PENDRIVE DETECTED: {drive} <<<\033[0m")
            for drive in removed_drives:
                print(f"[{get_timestamp()}] \033[91m!!! PENDRIVE REMOVED: {drive} !!!\033[0m")

            # Check for USB ports
            current_usb_info = get_all_usb_devices()
            current_ids = set(current_usb_info.keys())
            last_ids = set(last_usb_devices.keys())
            
            added_ids = current_ids - last_ids
            removed_ids = last_ids - current_ids

            for dev_id in added_ids:
                name = current_usb_info[dev_id]
                print(f"[{get_timestamp()}] \033[92m>>> USB INSERTED: {name} <<<\033[0m")
            
            for dev_id in removed_ids:
                name = last_usb_devices.get(dev_id, "Unknown Device")
                print(f"[{get_timestamp()}] \033[91m!!! USB DISCONNECTED: {name} !!!\033[0m")

            last_drives = current_drives
            last_usb_devices = current_usb_info
            
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n[{get_timestamp()}] Monitor stopped by user.")

if __name__ == "__main__":
    run_monitor()
