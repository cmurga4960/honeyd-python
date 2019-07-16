#!/usr/bin/env python
"""HPfeeds_logger.py is reponsible for connecting to an hpfeeds broker and submitting the attack-related information"""
import logging
import socket
from configparser import ConfigParser, NoSectionError, NoOptionError

import hpfeeds
import gevent

logger = logging.getLogger(__name__)


class HPFeedsLogger(object):
    """HPFeedsLogger connects to a broker and published the data stored in the attack_event dictionary"""
    def __init__(self, config_file):
        """Function initializes the HPfeeds logger
        Args:
            config_file : name of the honeypot configuration file
        """
        logger.debug('Initializing hpfeeds logger.')
        parser = ConfigParser()
        parser.read(config_file)
        self.enabled = False
        self.reconnect = True
        self._initial_connection_happened = False
        try:
            if parser.getboolean("hpfeeds", "enabled"):
                self.host = parser.get("hpfeeds", "host")
                self.port = int(parser.getint("hpfeeds", "port"))
                self.timeout = int(parser.get("hpfeeds", "timeout"))
                self.ident = parser.get("hpfeeds", "ident")
                self.secret = parser.get("hpfeeds", "secret")
                self.channels = parser.get("hpfeeds", "channels")
                self.max_retries = 5
                self.enabled = True
                self.hpc = None
                gevent.spawn(self._start_connection)
        except (NoSectionError, NoOptionError):
            logger.exception('Exception: Incomplete honeyd.cfg configuration. Hpfeeds logging is disabled.')
            self.enabled = False

    def _start_connection(self):
        """Function connects to the hpfeeds broker"""
        logger.debug('Connecting to hpfeeds broker.')
        try:
            self.hpc = hpfeeds.new(self.host, self.port, self.ident, self.secret, self.timeout, self.reconnect)
            self._initial_connection_happened = True
        except hpfeeds.FeedException:
            logger.exception('Exception: Cannot connect to hpfeeds service.')

    def publish(self, attack_event):
        """Function publishes the attack-related data to the broker
        Args:
            attack_event : dictionary containing the information
        """
        retries = 0
        if self._initial_connection_happened:
            while True:
                if retries >= self.max_retries:
                    break
                try:
                    if attack_event is not None:
                        self.hpc.publish(self.channels, attack_event)
                except socket.error:
                    retries += 1
                    gevent.spawn(
                        self._start_connection,
                        self.host,
                        self.port,
                        self.ident,
                        self.secret,
                        self.timeout,
                        self.reconnect)
                    gevent.sleep(0.5)
                else:
                    break
            error_msg = self.hpc.wait()
            logger.warning(error_msg)
        else:
            logger.warning('Not logging event because initial hpfeeds connection has not happend yet')
