#!/usr/bin/env python2
# -*- python -*-

import re
import os
import ldap
import ConfigParser
import subprocess
import calendar
import datetime
import pickle
import struct
import argparse
import logging
from socket import (
    socket,
    AF_INET,
    SOCK_STREAM,
)


ldap_base = 'OU=Users,OU=Organic Units,DC=cern,DC=ch'
ldap_query = "(memberof:1.2.840.113556.1.4.1941:=cn=%s,OU=e-groups,OU=Workgroups,DC=cern,DC=ch)"

deep_fs_output = "Overview for user (.*) : scanned (.*) directories/files, safe fix: (.*) unsafe fix: (.*) plaindir fix: (.*) skipped: (.*) wrong bits: (.*)"


class DeepFS:

    def __init__(self, configs, logger):
        self.configs = configs
        self.current_dir = os.path.dirname(os.path.realpath(__file__))
        self.logger = logger

    def _send_metrics(self, metrics):
        """
        Send metrics to the metrics server for analysis in Grafana.
        """

        self.logger.info("sending metrics to graphite: %s" % metrics)

        try:
            # Serialize the message and send everything in on single package
            payload = pickle.dumps(metrics, protocol=2)
            header = struct.pack("!L", len(payload))
            message = header + payload

            # Send the message
            conn = socket(AF_INET, SOCK_STREAM)
            conn.settimeout(2)
            conn.connect((self.configs['graphite_server'],
                        int(self.configs['graphite_server_port_batch'])))
            conn.send(message)
            conn.close()
            self.logger.info("Metrics sent")
        except Exception as ex:
            self.logger.error("Failed to send metrics: %s"% ex)

    def create_metrics(self, nusers, scanned, safe, unsafe, plaindir, skipped, wrongbits, error):
        date = calendar.timegm(datetime.datetime.utcnow().timetuple())
        metrics = [
            (".".join([self.configs['base_metrics_path'], 'deepfsscan', 'nusers']), (date, nusers)),
            (".".join([self.configs['base_metrics_path'], 'deepfsscan', 'scanned']), (date, scanned)),
            (".".join([self.configs['base_metrics_path'], 'deepfsscan', 'safe']), (date, safe)),
            (".".join([self.configs['base_metrics_path'], 'deepfsscan', 'unsafe']), (date, unsafe)),
            (".".join([self.configs['base_metrics_path'], 'deepfsscan', 'plaindir']), (date, plaindir)),
            (".".join([self.configs['base_metrics_path'], 'deepfsscan', 'skipped']), (date, skipped)),
            (".".join([self.configs['base_metrics_path'], 'deepfsscan', 'wrongbits']), (date, wrongbits)),
            (".".join([self.configs['base_metrics_path'], 'deepfsscan', 'error']), (date, error))
        ]
        return metrics

    def scan_user(self, user, fix):
        machine_command = "%s/cernbox-share verify --deep-fs-check%s %s" % (self.current_dir, " --fix" if fix else "", user)
        return_code, output, error = runcmd(machine_command)

        if return_code != 0:
            self.logger.debug(output)
            raise Exception()

        line = ""
        for line in output.splitlines():
            line = line.strip()
            self.logger.debug(line)

        # last line should have the results of the test...
        search = re.search(deep_fs_output, line)
        if not search:
            raise Exception()

        return search.groups()

    def scan_users(self, users, fix):
        nusers = len(users)
        scanned = 0
        safe = 0
        unsafe = 0
        plaindir = 0
        skipped = 0
        wrongbits = 0
        error = 0

        for user in users:
            try:
                scan_output = self.scan_user(user, fix)
                self.logger.info("User:%s, scanned:%s, safe:%s, unsafe:%s, plaindir:%s, skipped:%s, wrongbit:%s" % scan_output)
                (usr, _scanned, _safe, _unsafe, _plaindir, _skipped, _wrongbits) = scan_output
                scanned += int(_scanned)
                safe += int(_safe)
                unsafe += int(_unsafe)
                plaindir += int(_plaindir)
                skipped += int(_skipped)
                wrongbits += int(_wrongbits)
            except Exception:
                self.logger.warning("User %s gave no results" % user)
                error += 1

        return (nusers, scanned, safe, unsafe, plaindir, skipped, wrongbits, error)

    def get_users(self):
        egroup = self.configs['deepfs_egroup']
        con = ldap.initialize(self.configs['ldap_server'])
        info = con.search_s(ldap_base, ldap.SCOPE_SUBTREE, ldap_query % egroup)
        # only get main account for now TODO
        return [user[1]['cn'][0] for user in info]

    def do(self, users=None, send_metrics=False, fix=False):
        if not users:
            users = self.get_users()

        results = self.scan_users(users, fix=fix)

        if send_metrics:
            metrics = self.create_metrics(*results)
            self._send_metrics(metrics)


def configure(config_path):
    cp = ConfigParser.SafeConfigParser()
    cp.readfp(open(config_path, 'r'))
    config = {}
    for name, value in cp.items('general'):
        config[name] = value
    return config


def runcmd(cmd):
    process = subprocess.Popen(cmd.split(" "),
                               shell=False,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT)
    stdout, stderr = process.communicate()
    return (process.returncode, stdout, stderr)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--sendmetrics', default=False, const=True, action="store_const", dest="send_metrics")
    parser.add_argument('--fix', default=False, const=True, action="store_const", dest="fix")
    parser.add_argument("-v", "--verbose", action="store_true", dest="verbose")
    args = parser.parse_args()

    config = configure("/etc/cboxshareadmin.ini")

    format = '%(asctime)s %(levelname)s\t %(message)s'
    logging.basicConfig(level=logging.INFO, format=format)
    logger = logging.getLogger('deepfs')
    if args.verbose:
        logger.setLevel(logging.DEBUG)

    deepfs = DeepFS(config, logger)
    deepfs.do(send_metrics=args.send_metrics, fix=args.fix)
