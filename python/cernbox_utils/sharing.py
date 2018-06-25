import cernbox_utils
import subprocess
import os

# remove duplicates, preserving order
def squash(seq):
    seen = set()
    seen_add = seen.add
    return [x for x in seq if not (x in seen or seen_add(x))]


# convert DB share object inot EOS ACL object
def share2acl(s):
   from cernbox_utils.eos import EOS as eos

   # this is the expected ACL entry in the shared directory tree
   acl = eos.AclEntry(name=s.share_with)

   if s.share_with is None:		# Share by link
      acl.entity = "-"
   elif is_egroup(s.share_with):	# Share with egroups
      acl.entity = "egroup"
   else:				# Authenticated shares
      acl.entity = "u"

   if s.permissions == 1:
      acl.bits = "rx"
   else:
      acl.bits = "rwx+d"

   return acl

def crud2db(crud):
    if crud == 'r':
        return 1
    if crud == 'rw':
        return 15
    raise ValueError(crud)

# oc_share table permissions: anything bigger than 1 is "rw"
def db2crud(db):
    if db == 1:
        return "r"
    elif db > 1:
        return "rw"
    else:
        raise ValueError(db)


# convert CRUD specification (user) to EOS ACL bits
def crud2acl(crud):
    if crud == 'r':
        return 'rx'
    if crud == 'rw':
        return 'rwx+d'
    raise ValueError(crud)

# convert EOS ACL bits to CRUD specification (user)
def acl2crud(bits):
    if bits == 'rx':
        return 'r'
    if bits in ['rwx!m','rwx+d']:
        return 'rw'
    raise ValueError(crud)


def is_egroup(name):
   return '-' in name

def split_sharee(sharee):
    entity,who = sharee.split(":")  # this may also raise ValueError
    if not entity in ['u','egroup', 'fed']:
        raise ValueError()
    return entity,who


def check_can_share(owner,sharee):
    
    entity,who = split_sharee(sharee)

    if entity == 'u' and who == owner:
        raise ValueError("cannot share with self '%s'"%owner)

# TODO: rename to get_
def check_share_target(path,owner,eos,config):
      """ Return EOS file object for path.
      If path does not exist return None.
      If path is not sharable raise ValueError() 
      """
      logger = cernbox_utils.script.getLogger('sharing')

      import os

      if not path.startswith(config['eos_prefix']):
         raise ValueError("path '%s' should start with '%s'"% (path,config['eos_prefix']))

      try:
         f = eos.fileinfo(path)
      except subprocess.CalledProcessError,x:
         if 'error: cannot stat' in x.stderr:
            return None
         else:
            logger.error(repr(x.stderr))
            raise

      # make sure it is a folder, not a file
   
      if not f.is_dir():
         raise ValueError("Authenticated shares not supported for individual files... %s"%f.file)

      # get the top level

      if os.path.normpath(f.file).startswith(os.path.join(config['eos_prefix'],owner[0],owner)):
         top_level = os.path.join(config['eos_prefix'],owner[0],owner)
      elif os.path.normpath(f.file).startswith(config['eos_project_prefix']):
         # check eligibility based on admin/writers egroup?
         print_json_error("NotImplemented")
         raise NotImplemented()
      else:
         raise ValueError("Cannot share outside of home and project directories %s"%path)

      return f

def update_acls(fid,eos,db,owner=None,dryrun=True):
    """ Simple update strategy: override the whole tree in top-down order.

    finfo 
    """
    
    nodes = compute_acls(fid,eos,db,owner)

    # PENDING: send this stuff to EOS to be processed server-side
    # it is processed in order...
    # WARNING: this deletes any acls set by hand, in the case of wwweos in user homedirs, they is a corresponding share
    
    for node in nodes:
        eos.set_sysacl_r(node.file,eos.dump_sysacl(node.share_acl),dryrun=dryrun)
    

    return 0
    

def compute_acls(fid,eos,db,owner=None):
    """ Compute sharing ACLs for the directory tree specified by fid.

    Returns a list of EOS.FileInfo objects (nodes) with additional attribute share_acl. 

    The share_acl specifies the full list of ACLs for the node which result from any parent shares.

    The first item is the directory node specified by fid. The following items are shared subdirectories (if any).
    The list fully describes the ACL status of the tree rooted at fid and is sorted in top-down order. 

    The share_acl entries are normalized:
     * Within each shared node the ACL entries are sorted alphabetically
     * In case of nested shares, the corresponding node ACL entries are added in top-down order to the list
     * Hence, the share_acl is not globally sorted
     * Duplicate entries are globally removed

    """

    logger = cernbox_utils.script.getLogger('sharing')

    # 1. entry point is a path on storage (via fid) which may but does not have to have a corresponding share

    entry_point = eos.fileinfo("inode:"+fid)
    entry_point_is_shared = False

    if not owner:
        try:
            logger.debug("getting default share owner from password database: %s", entry_point.uid)
            import pwd
            owner=pwd.getpwuid(int(entry_point.uid)).pw_name

        except:
            logger.error("USER_NOT_FOUND: share owner uid %s does not exist",entry_point.uid)
            raise


    logger.debug("share_owner: %s",owner)

    # TODO: check: entry point must be a directory

    # 2. calculate base ACL for the entry path

    def is_ancestor(p1,p2):
       """ True if p1 is a (possibly indirect) ancestor (parent) of p2.
       Paths p1,p2 are assumed to be normalized and not ending with a slash.
       """
       # append trailing slash, otherwise directories which basename is a substring give false positive,
       # e.g.: /eos/user/k/kuba/tmp.readonly /eos/user/k/kuba/tmp
       return p2.startswith(p1+'/')

    def is_descendant(p1,p2):
       """ True if p1 is a (possibly indirect) descendant (child) of p2.
       Paths p1,p2 are assumed to be normalized and not ending with a slash.
       """
       return is_ancestor(p2,p1)

    # first squash the sharing table such that each path node is represented exactly once
    # and extract ancestors and descendants of the entry point
    # entry point is its own descendant (if exists)
    shared_nodes = {}
    descendant_nodes = {}
    ancestor_nodes = {}

    for s in db.get_share(owner=owner,share_type='regular'):

       try:
          node = shared_nodes[s.item_source]
       except KeyError:
           try:
               node = shared_nodes[s.item_source] = eos.fileinfo("inode:"+s.item_source)
               node.share_acl = [] # augment fileinfo struct with new attribute
           except subprocess.CalledProcessError,x:
               if x.returncode == 2:
                   # eos entry does not exist
                   logger.warning("DANGLING_SHARE id=%d owner=%s sharee=%s target='%s' fid=%s",s.id,s.uid_owner,s.share_with,s.file_target,fid)
                   continue              

       #print 'share',node.file,node.fid

       try:
          node.share_acl.append(share2acl(s))
       except Exception,x:
          logger.error("Share consistency problem: %s %s %s",s.id,x,s)
          continue

       if is_ancestor(node.file,entry_point.file):
          ancestor_nodes.setdefault(node.file,node)

       if is_descendant(node.file,entry_point.file): 
          descendant_nodes.setdefault(node.file,node)

       if node.file == entry_point.file:
          descendant_nodes.setdefault(node.file,node)
          entry_point_is_shared = True

    base_acl = [eos.AclEntry(entity="u",name=owner,bits="rwx!m")] # owner, project egroups, ...

    ancestor_acl = [base_acl]

    #  for all share ancestors of the entry path add the corresponding ACL entry in top-down order

    logger.debug('entry_point: %s', entry_point.file)
    logger.debug('base_acl: %s',base_acl)
    logger.debug('ancestors: %s', [(path,sorted(ancestor_nodes[path].share_acl)) for path in sorted(ancestor_nodes)])

    for path in sorted(ancestor_nodes):
       ancestor_acl.append(sorted(ancestor_nodes[path].share_acl))

    ancestor_acl = squash(sum(ancestor_acl,[])) # small optimization: remove duplicate entries (preserving order)

    logger.debug('ancestor_acl: %s',ancestor_acl)

    node_status = []

    # apply base ACL of the entry point

    if not entry_point_is_shared:  #  entry_point ACL must be set separately
       entry_point.share_acl = ancestor_acl
       node_status.append(entry_point)
       logger.debug('add_node_status: %s %s', node_status[-1].file, node_status[-1].share_acl)

    # apply ACL to each path which corresponds to a descendant share in top-down order by adding corresponding ACL entry to the base ACL
    # if entry point is shared it will be the first item in the descendant list
    logger.debug('descendants: %s', [(path,sorted(descendant_nodes[path].share_acl)) for path in sorted(descendant_nodes)])

    for path in sorted(descendant_nodes):
       acls = ancestor_acl[:]

       # add ACLs of all ancestors of current path which are in the descendant_nodes
       acls.extend(sum([sorted(n.share_acl) for p,n in sorted(descendant_nodes.items()) if is_ancestor(n.file,path)],[])) # flatten the list

       # add ACL for this path itself
       acls.extend(sorted(descendant_nodes[path].share_acl))

       node = descendant_nodes[path]
       node.share_acl = squash(acls)
       
       node_status.append(node) # small optimization: remove duplicate entries (preserving order)

       logger.debug('add_node_status: %s %s', node_status[-1].file, node_status[-1].share_acl)


    return node_status

class ShareNode(cernbox_utils.script.Data):
   _names = ['inode','owner','shares']


def collapse_into_nodes(shares):
    """
    Collapse flat share list into a list of nodes.
    """

    nodes = {}

    for s in shares:

        nodes.setdefault(s.item_source,ShareNode(inode=s.item_source,owner=s.uid_owner,shares=set()))

        nodes[s.item_source].shares.add(s)

    return nodes


def list_shares(user,role,groups,fid,share_type,flat_list,include_broken,db,eos):
    """ Return JSON-style dictionary listing all shares for a user in a role of "owner" or "sharee". 
    Each shared directory has one entry (and multuple shared_with entries if applicable).

    The fid may be left None. If fid is provided, the list will be limited to shares on the directory.

    Output modifiers: 
        - flat_list = as in the underlying db.
        - include_broken = shares which do not have anymore a corresponding filesystem object
    """

    logger = cernbox_utils.script.getLogger('sharing')

    user=user.strip()
    assert(user)
 
    assert(role in ['owner','sharee'])
 
    logger = cernbox_utils.script.getLogger('sharing')
 
    if role == "owner":
       shares=db.get_share(owner=user,fid=fid,share_type=share_type)
    else:
       shares=db.get_share(sharee=user,fid=fid,share_type=share_type)  

       for g in groups:
           shares.extend(db.get_share(sharee=groups,fid=fid))
 
    import datetime
    def dtisoformat(x):
       if x:
          return x.isoformat()
       else:
          return ""
 
    if flat_list:
       cnt=0
       retobj = {}
       for s in shares:
          logger.debug("Processing share: %s %s->%s %s %s",s.id,s.uid_owner,s.share_with,s.item_source,str(s.file_target))
 
          try:
             share_path = eos.fileinfo("inode:"+s.item_source).file
          except  subprocess.CalledProcessError,x:
             if x.returncode == 2:
                # eos entry does not exist
                logger.warning("DANGLING_SHARE id=%d owner=%s sharee=%s target='%s' inode=%s",s.id,s.uid_owner,s.share_with,s.file_target,s.item_source)
                share_path=None

 
          if share_path or include_broken:
             retobj[s.id] = {'uid_owner':s.uid_owner,'uid_initiator':s.uid_initiator,'share_id':s.id, 'share_with':s.share_with,'type':s.share_type,'target_inode':s.item_source,'target_name':s.file_target, 'permissions':s.permissions, 'created' : datetime.datetime.fromtimestamp(s.stime).isoformat(), 'expires' : dtisoformat(s.expiration), 'token':s.token, 'target_path':share_path }
 
       return retobj

    else:
       retobj = []
       nodes = collapse_into_nodes(shares)
       for target_id in nodes:
          try:
             f = eos.fileinfo("inode:"+target_id)
             target_path,target_size=f.file,f.treesize
          except  subprocess.CalledProcessError,x:
             if x.returncode == 2:
                # eos entry does not exist
                logger.warning("DANGLING_SHARE inode=%s",target_id)
                target_path,target_size=None,0

 
          if target_path or include_broken:
             retobj.append({'path':target_path, 'inode':target_id, 'size':target_size, 'shared_by':nodes[target_id].owner, 'shared_with' : []})
             for s in nodes[target_id].shares:
                acl = share2acl(s)
                retobj[-1]['shared_with'].append({'entity':acl.entity,'name':acl.name,'permissions':db2crud(s.permissions),'created':datetime.datetime.fromtimestamp(s.stime).isoformat()})
 
       return retobj


def add_share(owner,path,sharee,acl,eos,db,config,storage_acl_update=True):

      logger = cernbox_utils.script.getLogger('sharing')

      check_can_share(owner,sharee)

      share_with_entity,share_with_who = split_sharee(sharee)

      f = check_share_target(path,owner,eos,config)

      if not f:
          raise ValueError("Not found: %s"%path)

      # ... continue from common code above

      ACL = {'r':'read','rw':'read-write'}
      ENTITY = {'u':'user','egroup':'egroup', 'fed':'federated'}

      logger.info("Add %s share for %s %s to tree %s",ACL[acl],ENTITY[share_with_entity],share_with_who,path)
 
      # FIXME: do not use pound for this anymore (#): breaks HTTP standard and client browsers...
      file_target="/%s (#%d)" %(os.path.basename(os.path.normpath(f.file)),int(f.ino))

      # FIXME: poor's man solution: owncloud does not have constraints in the oc_share table
      # try to insert share entry, bailout if already exists...

      shares=db.get_share(sharee=share_with_who,owner=owner,fid=f.ino)

      if shares:
         msg="Share already exists, share id %d"%shares[0].id
         logger.error(msg)
         raise ValueError(msg) # TODO: BAD REQUEST
      else:
         db.insert_folder_share(owner,share_with_entity,share_with_who,int(f.ino),file_target,cernbox_utils.sharing.crud2db(acl))

      try:
         # modify storage ACL
         if storage_acl_update:
            cernbox_utils.sharing.update_acls(f.ino,eos,db,owner,dryrun=False)
      except CalledProcessError,x:
         logger.critical("Something went pretty wrong... %s %s stdout %s stderr %s",hash(x),x,x.stdout,x.stderr)
         #rollback the insert?
         raise
      except Exception,x:
         logger.critical("Something went pretty wrong... %s %s",hash(x),x)
         #rollback the insert?
         raise


# Federated Sharing: External shares
def add_external_share(remote,remote_id,share_token,password,name,owner,user,db):
    """ Add an external share
        (to be confirmed by 'accept_external_share' once the user accepted it)
    """

    logger = cernbox_utils.script.getLogger('external_shares')

    logger.info("Add external share %s owned by %s from %s for user %s",name,owner,remote,user)

    ext_share=db.get_external_share(remote,name,owner,user) # TODO: Should we leverage on share_token instead?

    if ext_share:
       msg="Share already exists, resource %s owned by %s from %s for user %s"%(ext_share[0].name,ext_share[0].owner,ext_share[0].remote,ext_share[0].user)
       logger.error(msg)
       raise ValueError(msg) # TODO: Bad request
    else:
       db.insert_external_share(remote,remote_id,share_token,password,name,owner,user)



#def accept_exterinal_share(remote,remote_id,share_token,name,owner,user,mountpoint,db):
def accept_external_share(remote,name,owner,user,mountpoint,db):
    """ Accept a (previously added) external share.
    """

    logger = cernbox_utils.script.getLogger('external_shares')

    logger.info("Accept external share %s owned by %s from %s for user %s",name,owner,remote,user)

    ext_share=db.get_external_share(remote,name,owner,user)

    if ext_share:
       db.accept_external_share(ext_share[0].id,mountpoint)
    else:
       msg="Share does not exist, resource %s owned by %s from %s for user %s"%(ext_share[0].name,ext_share[0].owner,ext_share[0].remote,ext_share[0].user)
       logger.error(msg)
       raise ValueError(msg) # TODO: BAD REQUEST


def remove_external_share(remote,name,owner,user,db):
    """ Delete an external share.
    """

    logger = cernbox_utils.script.getLogger('external_shares')

    logger.info("Remove external share %s owned by %s from %s for user %s",name,owner,remote,user)

    ext_share=db.get_external_share(remote,name,owner,user)

    if ext_share:
       db.delete_external_share(ext_share[0].id)
    else:
       msg="Share does not exist, resource %s owned by %s from %s for user %s"%(ext_share[0].name,ext_share[0].owner,ext_share[0].remote,ext_share[0].user)
       logger.error(msg)
       raise ValueError(msg) # TODO: BAD REQUEST


def list_external_shares(db,remote=None,owner=None,user=None,accepted=None):
    """ Return JSON-style dictionary listing all shares for
        1.  a local user in a role of "sharee" ("list-external-shared-with")
        2a. a remote server in a role of host for the shared resources ("list-external-shared-by")
        2b. a remote user in a role of "owner" ("list-external-shared-by")
    """

    logger = cernbox_utils.script.getLogger('external_shares')

    ext_shares = db.get_external_share(remote=remote,owner=owner,user=user,accepted=accepted)

    retobj = []

    for es in ext_shares:
       retobj.append({'remote':es.remote, 'remote-id':es.remote_id, 'share_token':es.share_token, 'password':es.password, 'name':es.name, 'owner':es.owner, 'user':es.user, 'mountpoint':es.mountpoint, 'mountpoint-hash':es.mountpoint_hash, 'accepted':es.accepted})

    return retobj



# Federated Sharing: Trusted servers
def add_trusted_server(url,db):
    """ Add a trusted server for federated sharing
    """

    logger = cernbox_utils.script.getLogger('trusted_servers')

    logger.info("Add %s as trusted server",url)

    trusted_server=db.get_trusted_server(url)
    if trusted_server:
       msg="Trusted server already exists, server url: %s"%url
       logger.error(msg)
       raise ValueError(msg) # TODO: BAD REQUEST
    else:
       db.add_trusted_server(url)



def remove_trusted_server(url,db):
    """ Remove a trusted server for federated sharing
    """

    logger = cernbox_utils.script.getLogger('trusted_servers')

    logger.info("Removing %s from trusted server list",url)

    trusted_server=db.get_trusted_server(url)
    if trusted_server:
       db.remove_trusted_server(trusted_server[0].id)
    else:
       msg="Server is not part of the trusted server list, server url: %s"%url
       logger.error(msg)
       raise ValueError(msg) # TODO: BAD REQUEST



def list_trusted_servers(db):
    """ Return JSON-style dictionary listing all trusted servers for federated sharing.
    """
    logger = cernbox_utils.script.getLogger('trusted_servers')

    trusted_servers=db.get_trusted_server()

    retobj = []

    for ts in trusted_servers:
       retobj.append({'url':ts.url, 'url_hash':ts.url_hash, 'token':ts.token, 'shared_secret':ts.shared_secret, 'status':ts.status, 'sync_token':ts.sync_token})

    return retobj

