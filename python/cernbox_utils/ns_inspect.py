import re
import cernbox_utils.script

EOSUserRE = '/eos/(user|project)/?([a-z])?/([a-z0-9]+)'
NSOutput = 'sys.acl=(.*) path=(.*)'

eos_machines = {
        "home" : {
            "i00":["d", "l", "n", "t", "z"],
            "i01":["a", "g", "j", "k", "w"],
            "i02":["h", "o", "r", "s", "y"],
            "i03":["b", "e", "m", "v", "x"],
            "i04":["c", "f", "i", "p", "q", "u"]
        },
        "project" : {
            "i00":["a", "e", "g", "j", "k", "q", "v"," y"],
            "i01":["b", "f", "h", "l", "n", "o", "p", "s", "w"],
            "i02":["c", "d", "i", "m", "r", "t", "u", "x", "z"]
        }
    }

class NSInspect:

    def __init__(self, config):
        self.config = config

    def _get_eos_machine(self, path):
        
        search = re.search(EOSUserRE, path)
        instance = search.group(1)
        letter = search.group(2)
        name = search.group(3)
        
        if instance == "user":
            instance = "home"
            
        if not letter:
            letter = name[0]
        
        for machine, letters in eos_machines[instance].items():
            if letter in letters:
                return "%s-%s" % (instance, machine)

        return instance

    def _get_command(self, path):
        eos_machine = self._get_eos_machine(path)
        return "/usr/bin/eos-ns-inspect dump --path %s --members eos%s-qdb:7777 --password-file /keytabs/%s_keytab --no-files --attr-query sys.acl" % (path, eos_machine, eos_machine)
    #     return "eos-ns-inspect dump --path %s --members %s-qdb:7777 --password-file /tmp/%s_keytab --no-files --attr-query sys.acl" % (path, eos_machine, eos_machine)

    def _run_script(self, path):
        eos_command = self._get_command(path)
        machine_command = "/usr/bin/ssh -oBatchMode=yes -oConnectTimeout=5 -oStrictHostKeyChecking=no -q -l root %s %s" % (self.config['nsinspect-machine'], eos_command)
        return cernbox_utils.script.runcmd(machine_command,shell=True)

    def _parse_output(self, output):
        to_return = []
        for line in output.splitlines():
            line = line.strip()
            search = re.search(NSOutput, line)
            if search:
                acl = search.group(1)
                path = search.group(2)
                to_return.append((path, acl))
        return to_return

    def inspect(self, path):
        return self._parse_output(self._run_script(path)[1])