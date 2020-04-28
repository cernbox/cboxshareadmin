#!/usr/bin/env python2
# -*- python -*-

import re, os
import ldap
import ConfigParser
import subprocess
import calendar, datetime
import pickle, struct
from socket import (
    socket,
    AF_INET,
    SOCK_STREAM,
)


ldap_base = 'OU=Users,OU=Organic Units,DC=cern,DC=ch'
ldap_query = "(memberof:1.2.840.113556.1.4.1941:=cn=%s,OU=e-groups,OU=Workgroups,DC=cern,DC=ch)"

deep_fs_output = "Overview for user (.*) : scanned (.*) directories, safe fix: (.*) unsafe fix: (.*) plaindir fix: (.*) skipped: (.*) wrong bits: (.*)"


class DeepFS:

    def __init__(self, configs):
        self.configs = configs
        self.current_dir = os.path.dirname(os.path.realpath(__file__))

    
    def _send_metrics(self, metrics):
        """
        Send metrics to the metrics server for analysis in Grafana.
        """

        print("sending metrics to graphite: %s" % metrics)

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
            print("Sent metrics!")
        except Exception as ex:
            print("Failed to send metrics: %s"% ex)


    def create_metrics(self, scanned, safe, unsafe, plaindir, skipped, wrongbits, error):
        date = calendar.timegm(datetime.datetime.utcnow().timetuple())
        metrics = [
                (".".join([self.configs['base_metrics_path'], 'deepfsscan', 'scanned']), (date, scanned)),
                (".".join([self.configs['base_metrics_path'], 'deepfsscan', 'safe']), (date, safe)),
                (".".join([self.configs['base_metrics_path'], 'deepfsscan', 'unsafe']), (date, unsafe)),
                (".".join([self.configs['base_metrics_path'], 'deepfsscan', 'plaindir']), (date, plaindir)),
                (".".join([self.configs['base_metrics_path'], 'deepfsscan', 'skipped']), (date, skipped)),
                (".".join([self.configs['base_metrics_path'], 'deepfsscan', 'wrongbits']), (date, wrongbits)),
                (".".join([self.configs['base_metrics_path'], 'deepfsscan', 'error']), (date, error))
            ]
        return metrics

    def scan_user(self, user):
        machine_command = "%s/cernbox-share verify --deep-fs-check --fix %s" % (self.current_dir, user)
        return_code, output, error = runcmd(machine_command)

        line = ""
        for line in output.splitlines():
            line = line.strip()
            print(line)

        # last line should have the results of the test...
        search = re.search(deep_fs_output, line)
        if not search:
            raise Exception()
        
        return search.groups()
        

    def scan_users(self, users):

        scanned = 0
        safe = 0
        unsafe = 0
        plaindir = 0
        skipped = 0
        wrongbits = 0
        error = 0

        for user in users:
            try:
                (usr, _scanned, _safe, _unsafe, _plaindir, _skipped, _wrongbits) = self.scan_user(user)
                scanned += int(_scanned)
                safe += int(_safe)
                unsafe += int(_unsafe)
                plaindir += int(_plaindir)
                skipped += int(_skipped)
                wrongbits += int(_wrongbits)
            except Exception:
                print("User %s gave no results" % user)
                error += 1

        return (scanned, safe, unsafe, plaindir, skipped, wrongbits, error)

    def get_users(self):

        egroup = self.configs['deepfs_egroup']
        con = ldap.initialize(self.configs['ldap_server'])
        info = con.search_s(ldap_base, ldap.SCOPE_SUBTREE, ldap_query % egroup)
        return [user[1]['cn'][0] for user in info] #only get main account for now TODO

    def do(self, users = None):

        if not users:
            users = self.get_users() 

        results = self.scan_users(users)
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
    stdout,stderr = process.communicate()

    if process.returncode != 0:
        x=subprocess.CalledProcessError(process.returncode,cmd)
        x.stderr=stderr
        x.stdout=stdout
        raise x

    return (process.returncode, stdout, stderr)

if __name__ == "__main__":
   config = configure("/etc/cboxshareadmin.ini")
   deepfs = DeepFS(config)
   deepfs.do()


