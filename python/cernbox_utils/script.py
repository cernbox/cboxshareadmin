
parser = None

def arg_parser(**kwds):
    """ Create an ArgumentParser with common options for scripts and tools.
    """
    import argparse
    global parser
    parser = argparse.ArgumentParser(**kwds)
    
    #parser.add_argument('--dry-run', '-n', action='store_true', help='show config options and print what tests would be run')
    parser.add_argument('--config','-c',dest="config",default="/etc/cbox/config/config.php",action="store",help='config file in original owncloud php format')

    group = parser.add_mutually_exclusive_group()

    group.add_argument('--quiet', '-q', dest='loglevel', action="store_const", const=logging.ERROR, help='do not produce output (other than errors)')
    group.add_argument('--debug', dest='loglevel', action="store_const", const=logging.DEBUG, help='produce very verbose output')
    #group.add_argument('--verbose', '-v', action="store_true", help='produce more output')

    parser.set_defaults(loglevel=logging.INFO)

    return parser

config = None

def configure(config_path):
    global config
    import string
    d = {}

    for line in file(config_path):
        line = line.strip()
        if line and '=>' in line:
            line = line.rstrip(',')
            key,value = line.split('=>')
            key = key.strip().strip("'")

            value = value.strip().strip("'")
            d[key] = value

    config = d
    return config


import logging

logger = None
def getLogger(name="",level=None):
   global logger
   if not logger:
      if level is None:
          level = logging.INFO  # change here to DEBUG if you want to debug config stuff

      #h = logging.StreamHandler()
      #fmt = logging.Formatter("%(levelname)s:%(name)s:%(message)s")
      #h.setFormatter(fmt)
      #h.setLevel(level)
      logging.basicConfig(level=level)

   names = ['cernbox']
   if name:
       names.append(name)

   l = logging.getLogger('.'.join(names))

   if not logger:
       logger = l
       #logger.addHandler(h)

   return l


import subprocess

def runcmd(cmd,ignore_exitcode=False,echo=True,allow_stderr=True,shell=True,log_warning=True):
    logger.debug('running %s', repr(cmd))

    process = subprocess.Popen(cmd, shell=shell,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    stdout,stderr = process.communicate()

    if echo:
        if stdout.strip():
            logger.info("stdout: %s",stdout)
        if stderr.strip():
            if allow_stderr:
                logger.info("stderr: %s",stderr)
            else:
                logger.error("stderr: %s",stderr)

    if process.returncode != 0:
        msg = "Non-zero exit code %d from command %s" % (ignore_exitcode,repr(cmd))
        if log_warning:
            logger.warning(msg)
        if not ignore_exitcode:
            raise subprocess.CalledProcessError(process.returncode,cmd)

    return (process.returncode, stdout, stderr)


class Data(object):
    """ Data objects is a convenient bag of ordered attributes (struct).

    Order is given by _names. Only attributes declared in _names should be set.

    These objects may be used in hashable collections such as sets.

    """
    _names = []

    def __init__(self,**kwds):
        for k in kwds:
            setattr(self,k,kwds[k])

    def __cmp__(self,other):
        return cmp(repr(self),repr(other))

    def __eq__(self,other):
        return repr(self)==repr(other)

    def __hash__(self):
        return hash(repr(self))

    def __repr__(self):
      s = self.__class__.__name__+"("
      attrs = []
      for n in self._names:
         try:
            attrs.append("%s=%s"%(n,repr(self.__dict__[n])))
         except KeyError: # ignore any missing _names
            pass
      s += ",".join(attrs)
      s += ")"
      return s
