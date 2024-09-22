#!/usr/bin/co2monitor.env python
import fcntl
import os
import socket
import sys
import time

import paho.mqtt.client as mqtt
from dotenv import load_dotenv


# based on code by henryk ploetz
# https://hackaday.io/project/5301-reverse-engineering-a-low-cost-usb-co-monitor/log/17909-all-your-base-are-belong-to-us


def decrypt(key, data):
    cstate = [0x48, 0x74, 0x65, 0x6D, 0x70, 0x39, 0x39, 0x65]
    shuffle = [2, 4, 0, 7, 1, 6, 5, 3]

    phase1 = [0] * 8
    for i, o in enumerate(shuffle):
        phase1[o] = data[i]

    phase2 = [0] * 8
    for i in range(8):
        phase2[i] = phase1[i] ^ key[i]

    phase3 = [0] * 8
    for i in range(8):
        phase3[i] = ((phase2[i] >> 3) | (phase2[(i - 1 + 8) % 8] << 5)) & 0xFF

    ctmp = [0] * 8
    for i in range(8):
        ctmp[i] = ((cstate[i] >> 4) | (cstate[i] << 4)) & 0xFF

    out = [0] * 8
    for i in range(8):
        out[i] = (0x100 + phase3[i] - ctmp[i]) & 0xFF

    return out


def hd(d):
    return " ".join("%02X" % e for e in d)


def now():
    return int(time.time())


if __name__ == "__main__":
    load_dotenv(dotenv_path=".co2monitor.env")
    # use lock on socket to indicate that script is already running
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        # Create an abstract socket, by prefixing it with null.
        s.bind("\0postconnect_gateway_notify_lock")
    except socket.error as e:
        # if script is already running just exit silently
        sys.exit(0)

    key = [0xC4, 0xC6, 0xC0, 0x92, 0x40, 0x23, 0xDC, 0x96]
    fp = open(sys.argv[1], "a+b", 0)
    HIDIOCSFEATURE_9 = 0xC0094806
    set_report = "\x00" + "".join(chr(e) for e in key)
    fcntl.ioctl(fp, HIDIOCSFEATURE_9, set_report)
    values = {}
    client = mqtt.Client("co2monitor")
    client.username_pw_set(username=os.getenv("MQTT_USER"), password=os.getenv("MQTT_PW"))
    client.connect(os.getenv("MQTT_HOST"), port=int(os.getenv("MQTT_PORT"), 1883), keepalive=60, bind_address="")
    print(f'Client is connect: {client.is_connected()}')

    stamp = now()

    while True:
        data = list(ord(e) for e in fp.read(8))
        decrypted = decrypt(key, data)
        if decrypted[4] != 0x0D or (sum(decrypted[:3]) & 0xFF) != decrypted[3]:
            print(hd(data), " => ", hd(decrypted), "Checksum error")
        else:
            op = decrypted[0]
            val = decrypted[1] << 8 | decrypted[2]
            values[op] = val

            if (0x50 in values) and (0x42 in values):
                co2 = values[0x50]
                tmp = values[0x42] / 16.0 - 273.15

                # check if it's a sensible value
                # (i.e. within the measuring range plus some margin)
                if co2 > 5000 or co2 < 0:
                    continue
                print("CO2: %4i TMP: %3.1f" % (co2, tmp))
                if now() - stamp > 30:
                    client.publish("co2monitor/co2", co2)
                    client.publish("co2monitor/temperature", tmp)
                    print(f"Published to MQTT {client.is_connected()}")
                    stamp = now()
