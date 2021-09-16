# ipscanner
Python script and module for scanning IPv4 addresses range. Shows basic information about devices and addresses:
 - IP
 - Availability
 - MAC address
 - Device vendor name
 - Device name
 - Ping
# Installation
**Windows**:

Download source code and unpack it.
In unpacked directory run:
```
pip install -r requirements.txt
```
**Linux**:

Download source code and unpack it or run
```git clone https://github.com/molney239/ipscanner.git```.
Then run
```
cd ipscanner
pip install -r requirements.txt
```
# Usage
Use python to run script with following options:
```
usage: ipscanner.py [-h] [-v --verbosity] [-p --packets-count]
                    [-t --ping-timeout] [--non-colorized]
                    addresses

Scans IPv4 addresses for availability.

positional arguments:
  addresses           Addresses for scan.

optional arguments:
  -h, --help          show this help message and exit
  -v --verbosity      Verbosity. 0: None. 1: Only available addresses. 2: Only
                      not available addresses. 3: All addresses.
  -p --packets-count  Ping packets count.
  -t --ping-timeout   Ping timeout (milliseconds).
  --non-colorized     Not colorize output. (Use if the output is not in the
                      correct format.)
```
To run from python, first download file and store it in your project directory. Then, write:
```
import ipscanner
```
# Examples
From **console**:
```
python ipscanner.py 192.168.1.0-192.168.1.255,8.8.8.8 -t 200 -v 1
```
Sample output:
```
IPv4: 192.168.1.1          | Available: YES      | MAC: a8:5e:45:2a:37:e8      | Vendor name: ASUSTek COMPUTER INC.          | Device name: router.asus.com      | Ping: 3.85ms
IPv4: 192.168.1.53         | Available: YES      | MAC: 78:44:76:81:40:c2      | Vendor name: None                           | Device name: User-PS              | Ping: 112.12ms
IPv4: 192.168.1.96         | Available: YES      | MAC: 80:91:33:cc:9d:2d      | Vendor name: AzureWave Technology Inc.      | Device name: Molney-Laptop        | Ping: 0.02ms
IPv4: 8.8.8.8              | Available: YES      | MAC: None                   | Vendor name: None                           | Device name: None                 | Ping: 9.16ms
```
Or from **python**:
```
import ipscanner
ipscanner.scan_range(['192.168.1.1', '8.8.8.8'], ping_timeout=500, verbosity=3)
```
Sample output:
```
IPv4: 192.168.1.1          | Available: YES      | MAC: a8:5e:45:2a:37:e8      | Vendor name: ASUSTek COMPUTER INC.          | Device name: router.asus.com      | Ping: 1.36ms
IPv4: 8.8.8.8              | Available: YES      | MAC: None                   | Vendor name: None                           | Device name: None                 | Ping: 11.07ms
```
