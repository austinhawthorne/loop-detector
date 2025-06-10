Simple tool to detect if a loop exists on a network.  Script will generate broadcast packets with a unique identfier and detect whether or not those packets are received back at the host.

Usage:  sudo python loop-detector.py

```
client1:~/loop-detector $ sudo python loop-detector.py -i eth0
Run ID (unique for this execution): 9b05ec60f2c242b680b7f61ec261ba2a
[Sender] Starting continuous broadcast every 1.0 seconds.
[Sniffer] Starting packet capture on interface: eth0
Continuous broadcast and loop detection are running. Press Ctrl+C to stop.
[Sender] Sent packet with sequence 1
[Sender] Sent packet with sequence 2
[Sender] Sent packet with sequence 3
[Sender] Sent packet with sequence 4
[Sender] Sent packet with sequence 5
```
