import cernbox_utils.script

logger = None 

def is_special_folder(path):
   import os.path
   "Special system directories are hidden and used to implement certain features such as atomic upload, versioning: .sys.v# .sys.a#"
   name = os.path.basename(os.path.normpath(path))
   for prefix in ['.sys.v#','.sys.a#']:
      if name.startswith(prefix):
         return True
   return False


def quote(s):
    # escape single quotes contained inside a single-quoted string for bash arguments
    s = s.replace("'","""'"'"'""") # this will replace any single quote character by this sequence '"'"'
    return "'"+s+"'"

class EOS:
    def __init__(self,mgmurl=''):
        self.mgmurl=mgmurl
        self.role = None
        global logger
        if not logger:
           logger = cernbox_utils.script.getLogger('eos')

        self.env = {'EOS_MGM_URL':mgmurl, 'XRD_NETWORKSTACK':'IPv4'} 
        # EOS_MGM_URL is needed for some convoluted cases such as 'eos cp -r' 
        # which actually spawns a subprocess without correctly passing the mgmurl as a command-line option
        
        self.cmd_opts = {} # default options for runcmd


        import logging
        if logger.getEffectiveLevel()<=logging.DEBUG:
           self.env['XRD_LOGLEVEL'] = 'Debug'


    def _eoscmd(self,*args,**kwds):

        try:
           role = kwds['role']
           if not role: role = self.role
        except KeyError:
           role=self.role

        eos = ["eos"]

        if role:
           uid,gid=role
           eos = eos + ["-r", str(uid),str(gid)] # running eos command with the role of the user

        # Backend might still be empty when used as ENV var
        if self.mgmurl:
           eos = eos + [self.mgmurl]

        #TODO: find /usr/bin/eos by PATH?

        cmd = eos + [x for x in args if x]  # filter out None or "" arguments
        return cmd

    def _runcmd(self,cmd,**opts):
       cmd_opts=self.cmd_opts.copy()
       cmd_opts.update(opts)
       return cernbox_utils.script.runcmd(cmd,env=self.env,shell=False,**cmd_opts)

    def ls(self,path,opts,role=None):

        eos = self._eoscmd('ls',opts,path,role=role)

        return self._runcmd(eos,echo=False)[1].splitlines()

    def fileinfo(self,spec,role=None):
        """ spec may be <path> or fid:<fid-dec> ...
        """

        eos = self._eoscmd('file info',spec,'-m',role=role)
                
        return _parse_mline(self._runcmd(eos,echo=False)[1])
    
    def fileinfo_r(self,path,type="",maxdepth=None,role=None):

        opts = ""
        if maxdepth:
            opts += "--maxdepth "+str(maxdepth)

        eos = self._eoscmd("find",type,"--fileinfo",opts,path,role=role)

        r = []
        for mline in self._runcmd(eos,echo=False)[1].splitlines():
            #logger.debug("fileinfo: %s",mline)
            mline=mline.strip()
            if mline: # skip empty lines
                r.append(_parse_mline(mline))
        return r

    def set_sysacl_r(self,path,acl,role=None,dryrun=True):
        return self.__set_sysacl(path,acl,role,dryrun,'-r')

    def set_sysacl(self,path,acl,role=None,dryrun=True):
        return self.__set_sysacl(path,acl,role,dryrun,'')

    def __set_sysacl(self,path,acl,role,dryrun,opt):
        eos = self._eoscmd("attr",opt,"set","sys.acl=%s"%acl,path,role=role)
        if dryrun:
            logger.warning("would run: %s",eos)
        else:
            self._runcmd(eos,echo=False)
        #logger.warning("eos -r 0 0 attr set sys.acl=%s %s",quote(eos.dump_sysacl(db_acls)),quote(f.file))

    class FileInfo(cernbox_utils.script.Data):
        def is_dir(self):
            return self.__dict__.has_key('container') # directory entries have the container counter 

        def is_file(self):
            return not self.is_dir()
                

    class AclEntry(cernbox_utils.script.Data):
       _names = ['entity','name','bits']

       def __str__(self):
           return ":".join([self.entity,self.name,self.bits])

       def __repr__(self):
           return str(self)

    def parse_sysacl(s):
        acl_list=[]
        for x in s.split(','):
            entity,name,bits = x.split(':')
            acl_list.append(EOS.AclEntry(entity=entity,name=name,bits=bits))
        return acl_list

    parse_sysacl = staticmethod(parse_sysacl)

    def dump_sysacl(acl_list):
        return ','.join([str(a) for a in acl_list])

    dump_sysacl = staticmethod(dump_sysacl)

####
# unit tests

def test_parse_mline(line):
    print _parse_mline("keylength.file=127 file=/eos/user/proc/recycle/2766/69973/#:#eos#:#user#:#c#:#cboxtu#:#smashbox-2015-06-12-163606-cboxsls.cern.ch#:#.00000000002ce1be.d container=0 files=20 mtime=1434976186.965261700 ctime=1434976186.965261700 mode=42700 uid=69973 gid=2766 fxid=002ce1be fid=2941374 ino=2941374 pid=356735 pxid=0005717f etag=2941374:1434976186 xattrn=sys.acl xattrv=u:cboxtu:rwx!m,u:kuba:x,u:ourense:x xattrn=sys.allow.oc.sync xattrv=1 xattrn=sys.forced.atomic xattrv=1 xattrn=sys.forced.blockchecksum xattrv=crc32c xattrn=sys.forced.blocksize xattrv=4k xattrn=sys.forced.checksum xattrv=adler xattrn=sys.forced.layout xattrv=replica xattrn=sys.forced.maximumsize xattrv=10000000000 xattrn=sys.forced.maxsize xattrv=10000000000 xattrn=sys.forced.nstripes xattrv=2 xattrn=sys.forced.space xattrv=default xattrn=sys.mtime.propagation xattrv=1 xattrn=sys.recycle xattrv=/eos/user/proc/recycle/ xattrn=sys.versioning xattrv=10")


##############################################################################
# utility functions

import os.path

def _parse_mline(line):
    """ Parse eos montoring output format (-m).

    Return dictionary with keys. Extended attributes are in an embedded dictionary accessible with 'xattr' key.
    """

    try:
        keylength = int(line.split()[0].split('=')[1])
    except IndexError:
        logger.critical("IndexError parsing mline: %s",repr(line))
        raise ValueError() # Notice: was IndexError before, changed from 'raise' on 14/11/2016
        
    file_marker = " file="
    pos = line.find(file_marker) + len(file_marker)

    filename = line[pos:pos+keylength]

    attrs = line[pos+keylength:].split()

    d = {'file':os.path.normpath(filename), 'xattr':{}}

    xattrn = None
    for a in attrs:
        # FIXED: split() is broken when v contains '=' character, WAS: k,v = a.split('=')
        i=a.find('=')
        if i == -1:
            logger.critical("Error parsing attribute '%s': '=' not found, mline is '%s'",repr(a),repr(line))
            raise ValueError()
        k = a[:i]
        v = a[i+1:]
        if k == 'xattrn':
            xattrn = v
        elif k == 'xattrv':
            assert(xattrn is not None)
            d['xattr'][xattrn] = v
            xattrn = None
        else:
            d[k]=v
    
    fi = EOS.FileInfo(**d)
    fi._names = d.keys()
    return fi
