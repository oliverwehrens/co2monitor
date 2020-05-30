# Co2Monitor

This connects a TFA Drostmann Co2 Mini Monitor to a Raspberry. It will publish it's values to a MQTT Service. The server is configured in the co2monitor.py file.

You need to have python2 and the paho mqtt python package installed.

By default it uses /dev/hidraw0 as Co2 Monitor device. If your settings are different change the co2monitor.service.

Copy the co2monitor.py to /usr/local/bin/co2monitor.py

The co2monitor.service file needs to go to /etc/systemd/system/

To start:

```
systemctl enable co2monitor.service
systemctl start co2monitor.service
```


This is a modification of https://github.com/wooga/office_weather
