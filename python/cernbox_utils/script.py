from .errors import CmdBadRequestError

parser = None

def arg_parser(**kwds):
    """ Create an ArgumentParser with common options for scripts and tools.
    """
    import argparse
    global parser
    parser = argparse.ArgumentParser(**kwds)
    
    #parser.add_argument('--dry-run', '-n', action='store_true', help='show config options and print what tests would be run')
    parser.add_argument('--config','-c',dest="configfile",action="store",help='config file')
    parser.add_argument('--logfile','-o',dest="logfile",action="store",help='logfile file')

    group = parser.add_mutually_exclusive_group()

    group.add_argument('--quiet', '-q', dest='loglevel', action="store_const", const=logging.ERROR, help='do not produce output (other than errors)')
    group.add_argument('--debug', dest='loglevel', action="store_const", const=logging.DEBUG, help='produce very verbose output')
    #group.add_argument('--verbose', '-v', action="store_true", help='produce more output')

    group = parser.add_mutually_exclusive_group()

    group.add_argument('--json', dest='json', action="store_true", default=False, help='Use JSON as data exchange format (this is an "API" call by another program). Print result on stdout in a JSON format.')

    #parser.set_defaults(loglevel=logging.INFO)
    parser.set_defaults(loglevel=logging.DEBUG)

    return parser

config = None

def configure(config_path):
    global config

    import ConfigParser

    cp = ConfigParser.SafeConfigParser()

    cp.readfp(file(config_path))

    d = {}

    for name,value in cp.items('general'):
        d[name] = value

    config = d
    return config


import logging

logger = None
logid = None

def getLogger(name="",level=None, filename=None):
   global logger
   if not logger:
      if level is None:
          level = logging.INFO  # change here to DEBUG if you want to debug config stuff

      import uuid
      logid = str(uuid.uuid1())
      #h.setLevel(level)
      #logging.basicConfig(level=level)

      format="%(asctime)-15s %(levelname)-5s:"+logid+":%(message)s"
      logging.basicConfig(level=level,format=format,filename=filename,filemode="a")

      # add screen output
      if filename:
          h = logging.StreamHandler()
          fmt = logging.Formatter("%(levelname)s:%(message)s")
          h.setFormatter(fmt)
          logging.root.addHandler(h)

   names = ['cernbox']
   if name:
       names.append(name)

   l = logging.getLogger('.'.join(names))

   if not logger:
       logger = l
       #logger.addHandler(h)

   return l


import subprocess

def runcmd(cmd,ignore_exitcode=False,echo=True,allow_stderr=True,shell=False,log_warning=True,env=None):
    logger.debug('running %s', repr(cmd))

    process = subprocess.Popen(cmd, shell=shell,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env)
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
            x=subprocess.CalledProcessError(process.returncode,cmd)
            x.stderr=stderr
            x.stdout=stdout
            raise x

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


def get_eos_backend(account, kind="home"):
    
    global config
    # We might not be using redis...
    if not config.get('redis_host') or \
        not config.get('redis_port') or \
        not config.get('redis_password'):
        return ''

    import redis

    logger.debug('getting eos backend for %s', account)

    r = redis.StrictRedis(host=config.get('redis_host'), port=config.get('redis_port'), db=0,
                          password=config.get('redis_password'))

    letter = account[0]

    if kind == "home":
        status = r.get('/eos/user/%s/%s' % (letter, account))
    else:
        status = r.get('/eos/%s/%s/%s' % (kind, letter, account))

    logger.debug('eos backend status: %s', status)

    if status == 'migrated':
        return 'eos%s-%s' % (kind, letter)

    elif status == 'not-migrated':
        return 'old%s' % kind

    elif status == 'ongoing-migration':
        raise CmdBadRequestError("Ongoing migration")

    else:
        default = r.get('default-user-not-found')

        if default == 'new-proxy':
            return 'eos%s-%s' % (kind, letter)

    return 'old%s' % kind


def get_eos_server(user, kind="home"):
    
    global config
    force_eos_mgm = config.get('force_eos_mgm')
    if force_eos_mgm:
        return config.get('eos_mgm_url')

    backend = get_eos_backend(user, kind)
    return get_eos_server_string(backend)


def get_eos_server_string(backend):
    global config
    if not backend:
        return config.get('eos_mgm_url')

    if  backend == 'oldhome' or backend == 'oldproject':
        return 'root://eosuser-internal.cern.ch'

    if 'newproject' in backend:
        return 'root://%s.cern.ch' % backend.replace('newproject', 'eosproject')

    return 'root://%s.cern.ch' % backend
