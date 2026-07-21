# Long Running Test

This sample application that tests repeatedly sending a fixed size packet for defined time period.

## Kconfig

The application is configurable via Kconfig to set the AP SSID, Password, TCP server IP address and
Port, and Test Duration.
*Update these values accordingly*

## Expected Flow

The expectation for this application is that it will:
* Connect to the AP
* Connect to the TCP server running on the AP
* Repeatedly send payload until N milliseconds have passed
* Disconnect from the AP

## Testing with a HalowLink

You can run this sample with MorseMicro HalowLink products.
Connect to the HalowLink AP via SSH and run the following command:
```
nc -ltp <TCP_SERVER_PORT>
```

*NB: Replace <TCP_SERVER_PORT> with the defined value in Kconfig*
