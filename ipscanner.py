#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""

Python script and module for scanning IPv4 addresses range. Shows basic information about devices and addresses.

Usage examples:
From console:
    pip3 install -r requirements.txt
    python3 ipscanner.py 192.168.1.0-192.168.1.255,8.8.8.8 -p 2 -t 200 -v 1
    This command starting script for scanning address in local network and 8.8.8.8 address.

From python:
    import ipscanner
    ipscanner.scan_range([192.168.1.0, 8.8.8.8], verbosity=3, ping_timeout=200)

 ========== LICENSE ==========

    The MIT License

    Copyright (c) 2021 molney239 and contributors

    Permission is hereby granted, free of charge, to any person obtaining a
    copy of this software and associated documentation files (the "Software"),
    to deal in the Software without restriction, including without limitation
    the rights to use, copy, modify, merge, publish, distribute, sublicense,
    and/or sell copies of the Software, and to permit persons to whom the
    Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in
    all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
    FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
    DEALINGS IN THE SOFTWARE.

 =============================

"""


# Libs
import ipaddress
import pythonping
import getmac
import requests
import socket
from termcolor import colored
from platform import system


__author__ = "molney239"
__copyright__ = 'Copyright 2021, ipscanner'
__license__ = 'The MIT License'
__version__ = '1.0.0'
__email__ = 'molney239@gmail.com'


# For correct colorized output in Windows.
if system() == "Windows":
    from colorama import init
    init()


class PingResult:
    def __init__(self, address: str, available: bool, ping_ms: int):
        self.address = address
        self.available = available
        self.ping_ms = ping_ms


class ScanResult:
    def __init__(self, address: str, available: bool, mac: str, vendor_name: str, device_name: str, ping_ms: int):
        self.address = address
        self.available = available
        self.mac = mac
        self.vendor_name = vendor_name
        self.device_name = device_name
        self.ping_ms = ping_ms


def parse_addresses(addresses: str):
    """
    Parses string to IPv4 range.

    :param addresses: Addresses string. Example: 192.168.1.0.192.168.1.255,8.8.8.8
    :return: Generator of strings with IPv4s.
    """
    for i in addresses.split(','):
        if i.count('-') == 0:
            yield i
        elif i.count('-') == 1:
            for j in range(int(ipaddress.IPv4Address(i.split('-')[0])),
                           int(ipaddress.IPv4Address(i.split('-')[1])) + 1):
                yield str(ipaddress.IPv4Address(j))
        else:
            raise ValueError("Invalid addresses range: " + i)


def print_result(result: ScanResult, colorized: bool = True) -> None:
    """
    Printing result of scan to console.

    :param result: ScanResult object.
    :param colorized: Colorize output. Disable, if the output is not in the correct format.
    """
    output = ""
    if colorized and system() == "Windows":
        output = "IPv4: {:29} | Available: {:17} | MAC: {:31} | Vendor name: {:30} | Device name: {:20} | Ping: {}"
    else:
        output = "IPv4: {:15} | Available: {:3} | MAC: {:17} | Vendor name: {:30} | Device name: {:20} | Ping: {}"
    if colorized:
        print(output.format(
            str(colored(result.address, 'blue')),
            str(colored("YES", 'green')) if result.available else str(colored("NO", 'red')),
            str(colored(str(result.mac), 'yellow')),
            str(result.vendor_name),
            str(result.device_name),
            str(result.ping_ms)) + "ms"
        )
    else:
        print(output.format(
            str(result.address),
            ("YES" if result.available else "NO"),
            str(result.mac),
            str(result.vendor_name),
            str(result.device_name),
            str(result.ping_ms)) + "ms"
        )


def ping(address: str, packets_count: int = 1, ping_timeout: int = 2000) -> PingResult:
    """
    Pings address.

    :param address: IP v4 address.
    :param packets_count: Packets count.
    :param ping_timeout: Timeout (milliseconds).
    :return: PingResult object.
    """
    if packets_count < 1:
        raise ValueError("Invalid ping packets count: " + str(packets_count))
    if ping_timeout < 0:
        raise ValueError("Invalid ping timeout: " + str(ping_timeout))
    result = pythonping.ping(address, count=packets_count, timeout=ping_timeout / 1000.0, verbose=False)
    return PingResult(address, result.success(), result.rtt_avg_ms)


def scan(address: str, packets_count: int = 1, ping_timeout: int = 2000) -> ScanResult:
    """
    Scans IP v4 address.

    :param address: Address.
    :param packets_count: Ping packets count.
    :param ping_timeout: Ping timeout (milliseconds).
    :return: ScanResult object.
    """
    ping_result = ping(address, packets_count=packets_count, ping_timeout=ping_timeout)
    mac = "None"
    vendor_name = "None"
    device_name = "None"
    if ping_result.available:
        mac = getmac.get_mac_address(ip=address)
        if mac is not None:
            url = "https://api.macvendors.com/"
            response = requests.get(url + mac)
            if response.status_code == 200:
                vendor_name = response.content.decode()
            device_name = socket.getfqdn(address)
        else:
            mac = "None"
    return ScanResult(
        address,
        ping_result.available,
        mac,
        vendor_name,
        device_name,
        ping_result.ping_ms
    )


def scan_range(addresses: iter, packets_count: int = 1, ping_timeout: int = 2000, verbosity: int = 0,
               colorized: bool = True) -> list:
    """
    Scans IP v4 addresses.

    Verbosity codes:
    0: None.
    1: Only available addresses.
    2: Only not available addresses.
    3: All addresses.

    :param addresses: Iterable object with addresses (strings).
    :param packets_count: Ping packets count.
    :param ping_timeout: Ping timeout (milliseconds).
    :param verbosity: Verbosity.
    :param colorized: Colorized output.
    :return: List of dictionaries with results.
    """
    results = []
    for address in addresses:
        result = scan(address, packets_count=packets_count, ping_timeout=ping_timeout)
        results.append(result)
        if (verbosity == 1 and result.available) or (verbosity == 2 and not result.available) or (verbosity == 3):
            print_result(result, colorized=colorized)
    return results


if __name__ == "__main__":
    import argparse

    # Parse console arguments.
    parser = argparse.ArgumentParser(description="Scans IPv4 addresses for availability.")
    parser.add_argument("addresses", metavar='addresses', type=str, help="Addresses for scan.")
    parser.add_argument("-v", metavar="--verbosity", type=int, default=3, help="Verbosity. " +
                                                                               "0: None. " +
                                                                               "1: Only available addresses. " +
                                                                               "2: Only not available addresses. " +
                                                                               "3: All addresses.")
    parser.add_argument("-p", metavar="--packets-count", type=int, default=1, help="Ping packets count.")
    parser.add_argument("-t", metavar="--ping-timeout", type=int, default=2000, help="Ping timeout (milliseconds).")
    parser.add_argument("--non-colorized", action="store_true",
                        help="Not colorize output. (Use if the output is not in the correct format.)")

    args = parser.parse_args()
    scan_range(parse_addresses(args.addresses), packets_count=args.p, ping_timeout=args.t, verbosity=args.v,
               colorized=not args.non_colorized)
