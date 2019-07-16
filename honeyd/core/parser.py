#!/usr/bin/env python
"""Parser.py is responsible for parsing the nmap-os-db and nmap-mac-prefixes files."""
import logging
import sys
import os
import mmap
import re
import random

logger = logging.getLogger(__name__)


class Parser(object):
    """Responsible for parsing the nmap-os-db and nmap-mac-prefixes files and creating the approrpiate personality structure."""

    def __init__(self, fingerprint_file, mac_file):
        """Function initializes the parser and obtains the open file descriptors
        Args:
            fingerprint_file : nmap-os-db file
            mac_file : nmap-mac-prefixes file
        """
        logger.debug('Initializing Nmap fingerprint parser.')
        fd_fingerprint_file = open(fingerprint_file, 'r')
        self.fingerprint_file = mmap.mmap(fd_fingerprint_file.fileno(), 0, access=mmap.ACCESS_READ)

        fd_mac_file = open(mac_file)
        self.mac_file = mmap.mmap(fd_mac_file.fileno(), 0, access=mmap.ACCESS_READ)

    def parse(self, personality):
        """Function parses the fingerprint file and creates a personality data structure
        Args:
            personality : name of the fingerprint personality
        Return:
            instance of a personality object defining network stack behavior
        """
        print(type(personality),personality) 
        logger.debug('Initializing personality for device %s', personality)
        # first occurence of fingerprint name and empty line delimiter
        start_index = self.fingerprint_file.find(str('Fingerprint ' + personality).encode())
        end_index = self.fingerprint_file.find('\n\n'.encode(), start_index)

        try:
            self.fingerprint_file.seek(start_index, os.SEEK_SET)
            fingerprint_section = self.fingerprint_file.read(end_index - start_index).splitlines()
        except ValueError:
            logger.exception('Exception: Personality %s not found.', personality)
            sys.exit(1)
        p = Personality()
        # File contents defined at https://nmap.org/book/osdetect-methods.html
        for line in fingerprint_section:
            print(type(line),line)
            line = line.decode('utf-8')
            if line.startswith('Fingerprint'):
                # free text description
                p.fp_name = line[len('Fingerprint '):]
            elif line.startswith('Class '):
                # vendor | OS family | OS generation | device type
                p.fp_class.append(
                    dict(zip(['vendor', 'family', 'generation', 'type'], line[len('Class '):].split('|'))))
            elif line.startswith('CPE '):
                # cpe:/(a|h|o):vendor:product:version:update:edition:language auto
                fp_cpe = line[len('CPE cpe:/'):].split(':')
                # strip the section indicating the generation method
                index = fp_cpe[-1].find(' ')
                if index != -1:
                    fp_cpe[-1] = fp_cpe[-1][:index]
                p.fp_cpe.append(
                    dict(zip(['part', 'vendor', 'product', 'version', 'update', 'edition', 'language'], fp_cpe)))
            elif line.startswith('SEQ('):
                # GCD % SP % ISR % TI % II % TS
                p.fp_seq = {key: value for (key, value) in (item.split('=')
                                                            for item in line[len('SEQ('):-1].split('%'))}
            elif line.startswith('OPS('):
                # O1 % O2 % O3 % O4 % O5 % O6
                p.fp_ops = {key: value for (key, value) in (item.split('=')
                                                            for item in line[len('OPS('):-1].split('%'))}
            elif line.startswith('WIN('):
                # W1 % W2 % W3 % W4 % W5 % W6
                p.fp_win = {key: value for (key, value) in (item.split('=')
                                                            for item in line[len('WIN('):-1].split('%'))}
            elif line.startswith('ECN('):
                # R % DF % T % TG % W % O % CC % Q
                p.fp_ecn = {key: value for (key, value) in (item.split('=')
                                                            for item in line[len('ECN('):-1].split('%'))}
            elif line.startswith('T'):
                # R % DF % T % TG % W % S % A % F % O % RD % Q
                fp_ti = {key: value for (key, value) in (item.split('=') for item in line[len('Ti('):-1].split('%'))}
                p.fp_ti.update({line[:2]: fp_ti})
            elif line.startswith('U1('):
                # R % DF % T % TG % IPL & UN % RIPL % RID % RUCK % RUD
                p.fp_u1 = {key: value for (key, value) in (item.split('=') for item in line[len('U1('):-1].split('%'))}
            elif line.startswith('IE('):
                # R % DFI % T % TG % CD
                p.fp_ie = {key: value for (key, value) in (item.split('=') for item in line[len('IE('):-1].split('%'))}
        return p

    def get_mac_oui(self, personality, vendor_list=None):
        """Function generates a proper MAC OUI according to given vendors, or randomly
        Args:
            personality : personality of the device
            vendor_list : list of vendors according to the nmap-mac-prefixes file
        """
        logger.debug('Initializing MAC OUI for device %s', personality)
        if vendor_list is None or not len(vendor_list):
            # in case no vendor list is given find try to find mac according to personality class vendor
            vendor_list = [item['vendor'] for item in personality.fp_class]
        while personality.mac_oui is None:
            if len(vendor_list):
                current_vendor = vendor_list.pop()
                # looking for exact matches
                match = re.match(r'^([0-9A-F]{6})\s' + current_vendor + '$', self.mac_file[:].decode('utf-8'), re.MULTILINE)
                if match is not None:
                    personality.mac_oui = match.group(1)
            else:
                logger.warning('Using random generated MAC address for personality: %s', personality.fp_name)
                personality.mac_oui = hex(random.randrange(16**6))[2:]

    def close_files(self):
        """Function closes file descriptors for nmap files"""
        logger.debug('Closing file descriptors for Nmap files.')
        self.fingerprint_file.close()
        self.mac_file.close()


class Personality(object):
    """Defines structure of device personalities, containing device MAC OUI and response requirements to nmap scans"""

    def __init__(self):
        """Function initializes the personality data structure"""
        self.mac_oui = None
        self.fp_name = None
        self.fp_class = list()
        self.fp_cpe = list()
        self.fp_seq = dict()
        self.fp_ops = dict()
        self.fp_win = dict()
        self.fp_ecn = dict()
        self.fp_ti = dict()
        self.fp_u1 = dict()
        self.fp_ie = dict()
