# Alpha Testing

This sample application tests the minimum basic requirements for the Alpha port
of the SoftMAC driver.
It tests:
* Wi-Fi Connect
* Wi-Fi Disconnect
* TCP ops via:
    * MQTT Publish
    * MQTT Subscribe

## Kconfig

The application is configurable via Kconfig to set the AP SSID, Password, MQTT Broker address and port.
*Please update these values accordingly*

## MQTT Service

This sample expects that the AP has `mosquitto` installed and is running the `tools/mqtt-forwarder.sh` script.

## Expected Flow

The expectation for this application is that it will:
* Connect to the AP
* Set up an MQTT subscription to `twister/output` for a Mosquitto service running on the AP
* Publish an MQTT message to `twister/input`
* Successfully receive a message on the aforementioned subscription
* Disconnect from the AP