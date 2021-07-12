#!/usr/local/bin/python
# -*- coding: utf-8 -*-
# Copyright © 2020 The vt-py authors. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Suspicious sightings given a list of network observables.

This scripts prints suspicious sightings related to a domain or IP address.
The scripts receives a file as input having a domain/IP address per line.
"""
import os
import sys
import argparse
import asyncio
import re
import csv

flibs = ['/home/raychorn/projects/securex.ai/vt-py', '/home/raychorn/projects/securex.ai/securex-shared']
if (not any([f in flibs for f in sys.path])):
    for f in flibs:
        sys.path.append(f)
import vt

from vyperlogix.dicts import SmartDict


IP_REGEX = re.compile(r'\d+\.\d+\.\d+\.\d+')


def is_ip_address(netloc):
    """Checks whether a given value is a IP address or not.

    Args:
        netloc: str, IP address to check.

    Returns:
        True or false
    """
    return IP_REGEX.match(netloc) is not None


def get_detection_rate(stats):
    """Get detection rate as string."""
    return f'{stats["malicious"]}/{sum(stats.values())}'


def print_results(results, netloc):
    """Print results for a given netloc.

    Results are only printed if there's a suspicious sighting.
    """
    if any(x is not None for x, _, _ in results):
        n_spaces = 50 - len(netloc)
        print(
                f'{netloc}{" " * n_spaces}'
                f'{"    ".join(f"{n} detected {t} [max:{m}]" for m, n, t in results if m)}')


async def get_netloc_relationship(apikey, netloc, rel_type):
    """Gets a netloc relationship and returns the highest detection rate."""
    path = 'ip_addresses' if is_ip_address(netloc) else 'domains'
    async with vt.Client(apikey) as client:
        it = client.iterator(f'/{path}/{netloc}/{rel_type}', limit=20)
        stats = [
                get_detection_rate(f.last_analysis_stats) async for f in it
                if f.last_analysis_stats['malicious']]

        if stats:
            text = rel_type.replace("_", " ")[:-1 if len(stats) <= 1 else None]
            return max(stats), len(stats), text
        else:
            return None, 0, ''


async def get_netloc_report_relationships(loop, apikey, netloc):
    """Gets report and relationships for a given network location."""
    if not netloc:
        return

    tasks = []
    async with vt.Client(apikey) as client:
        for rel_type in [
                'urls', 'downloaded_files', 'communicating_files', 'referrer_files']:

            tasks.append(loop.create_task(
                    get_netloc_relationship(apikey, netloc, rel_type)))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    print_results(results, netloc)

def main(args=None):
    if (args is None):
        parser = argparse.ArgumentParser( description='Get suspicious sightings related to a network observable.')

        parser.add_argument('--apikey', required=True, help='your VirusTotal API key')
        parser.add_argument('--path', required=True, type=argparse.FileType('r'),
                                                help='path to the file containing the domains and IPs.')
        parser.add_argument('--limit', type=int, default=20,
                                                help='number of items to process in every search.')
        args = parser.parse_args()
    else:
        args = SmartDict(**args)

    loop = asyncio.get_event_loop()
    tasks = []
    for n in args.path:
        tasks.append(loop.create_task( get_netloc_report_relationships(loop, args.apikey, n.strip())))

    # Wait until all tasks are completed.
    loop.run_until_complete(asyncio.gather(*tasks))
    loop.close()

def normalize_str(s):
    toks = s.split('"')
    __is__ = toks[-1] == ''
    _s = toks[1 if (__is__) else 0:-1 if (__is__) else len(toks) - 1]
    return ''.join(_s)

if __name__ == '__main__':
    the_args = {
            'apikey': '',
            'path': '',
            'limit': 20
        }
    src_path = '/home/raychorn/projects/securex.ai/attack-inferencer/data/CloudWatchData1_vpc-flowlogs-filtered_china_mobile.csv'
    ip_addresses = []
    the_args['apikey'] = '1179446f70b2f86bc3dfe396534c39e3a8a23cea9832167c17dd7fc862d0ed31'
    with open(src_path, 'r', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            retirees = []
            for k,v in row.items():
                _k = normalize_str(k)
                if (_k == '_id'):
                    retirees.append(k)
            for k in retirees:
                del row[k]
            row = {k:v for k,v in row.items() if (not k.startswith('__') and (not k.endswith('__'))) and (len(v.split('.')) == 4)}
            if (len(ip_addresses) < 20):
                ip_addresses.append(row.get(list(row.keys())[0]))
                ip_addresses = list(set(ip_addresses))
    if (0):
        fpath = os.sep.join([os.path.dirname(src_path), 'ip_addresses.txt'])
        with open(fpath, 'w', encoding='utf-8') as fOut:
            fOut.write('\n'.join(ip_addresses))
        the_args['path'] = [fpath]
        main(the_args)
    else:
        import requests
        args = SmartDict(**the_args)
        # https://www.virustotal.com/api/v3/ip_addresses/ip/comments
        for ip in ip_addresses:
            r = requests.get("https://www.virustotal.com/api/v3/ip_addresses/{}/comments".format(ip), headers={"content-type": "application/json", 'x-apikey': args.apikey})
            print(r.json())
            print(r.status_code)
