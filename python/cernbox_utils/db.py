import cernbox_utils.script

class ShareInfo(cernbox_utils.script.Data):
   _names = ['id','share_type','share_with','uid_owner','uid_initiator','parent','item_type','item_source','item_target','file_source','file_target','permissions','stime','accepted','expiration','token','mail_send']

   def _check_consistency(self):
      pass

class ExternalSharesInfo(cernbox_utils.script.Data):
   _names = ['id', 'remote', 'remote_id', 'share_token', 'password', 'name', 'owner', 'user', 'mountpoint', 'mountpoint_hash', 'accepted']

   def _check_consistency(self):
      pass

class TrustedServersInfo(cernbox_utils.script.Data):
   _names = ['id', 'url', 'url_hash', 'token', 'shared_secret', 'status', 'sync_token']

   def _check_consistency(self):
      pass


import MySQLdb


# mapping: column_name => index
#oc_share = dict([(name,i) for i,name in enumerate(['id','share_type','share_with','uid_owner','parent','item_source','item_target','file_source','file_target','permissions','stime','accepted','expiration','token','mail_send'])])



# quote strings to insert into MySQL DB
def quote(x):
   return '"'+x+'"'



# compute md5 digest
def md5_digest(x):
   import hashlib
   return hashlib.md5(x).hexdigest()



class ShareDB:

   def __init__(self):
      from cernbox_utils.script import config
      host,port=None,None

      if config['dbhost']:
         host = config['dbhost'].split(':')[0]
         try:
            port = int(config['dbhost'].split(':')[1])
         except IndexError:
            pass

      if port:
         db = MySQLdb.connect(host=host,port=port,user=config['dbuser'],passwd=config['dbpassword'],db=config['dbname'])
      else:
         db = MySQLdb.connect(host=host,user=config['dbuser'],passwd=config['dbpassword'],db=config['dbname'])

      self.db = db



   def get_share(self,fid=None,sharee=None,owner=None,share_type=None,share_time_greater_than=None,item_type=None,share_id=None):
      """ Get share information matchin target file id AND sharee name AND owner name AND share type ("link" or "regular").
      """
      cur = self.db.cursor()

      WHERE = []

      if share_id:
         WHERE.append('id = "%s"'%share_id)

      if fid:
         WHERE.append('file_source = "%s"'%fid)

      if sharee:
         WHERE.append('share_with = "%s"'%sharee)

      if owner:
         WHERE.append('uid_owner = "%s"'%owner)

      if share_time_greater_than:
         WHERE.append('stime > %s'%share_time_greater_than)

      if item_type:
         WHERE.append('item_type = "%s"'%item_type)

      if share_type:
         if share_type == "link": 
            WHERE.append('share_type = 3')

         if share_type == "regular": 
            WHERE.append('share_type != 3')

      if WHERE:
         WHERE = "WHERE " + (' and '.join(WHERE))
      else:
         WHERE = ""

      logger = cernbox_utils.script.getLogger('db')

      sql = "SELECT * FROM oc_share "+WHERE
      logger.debug(sql)

      cur.execute(sql)

      shares = []
      for row in cur.fetchall():
         s = ShareInfo()
         for i,name in enumerate(ShareInfo._names):
            setattr(s,name,row[i])            
         shares.append(s)
         logger.debug("ROW: %s",row)

      return shares

#   _names = ['id','share_type','share_with','uid_owner','parent','item_type','item_source','item_target','file_source','file_target','permissions','stime','accepted','expiration','token','mail_send']

   # TODO: https://its.cern.ch/jira/browse/CERNBOX-236



   def insert_file_share(self):
      pass
      #TODO: to be implemented
      return



   def insert_folder_share(self,owner,sharee_entity,sharee,fid,file_target,permissions,stime=None,initiator=None):
      cur = self.db.cursor()
      logger = cernbox_utils.script.getLogger('db')

      if initiator is None:
         initiator=owner

      assert(all(c.isalnum() for c in owner))
      assert(all(c.isalnum() for c in initiator))
      assert(all(c.isalnum() or c=='-' for c in sharee)) # egroups may have dash in the name

      if sharee_entity == 'fed':
         share_type = 6    # federated
      else:
         if '-' in sharee:
            share_type = 1 # group
         else:
            share_type = 0 # user

      assert(fid>0)
      assert(permissions>=0)
      assert(stime is None or stime>0)
      assert(file_target!="")

      item_source=fid
      item_target=quote("/%d"%fid)
      file_source=fid
      file_target=quote(file_target)
      
      if stime is None:
         import time
         stime = time.time()


      sql = 'INSERT INTO oc_share(share_type, share_with, uid_owner, uid_initiator, parent, item_type, item_source, item_target, file_source, file_target, permissions, stime) values (%d,%s,%s,%s,NULL,"folder",%d,%s,%d,%s,%d,%d)' % (share_type,quote(sharee),quote(owner),quote(initiator),item_source,item_target,file_source,file_target,permissions,stime);

      logger.debug(sql)
      cur.execute(sql)
      self.db.commit()



   def update_share(self,id,file_target=None):

      cur = self.db.cursor()
      logger = cernbox_utils.script.getLogger('db')
      
      set_cmd = []

      if file_target is not None:
         assert("'" not in file_target)
         set_cmd.append("file_target = '%s'"%file_target)

      if not set_cmd:
         raise ValueError("nothing to set")

      set_cmd = ",".join(set_cmd)

      sql="UPDATE oc_share SET %s WHERE id=%d;"%(set_cmd,id)

      logger.debug(sql)
      cur.execute(sql)
      self.db.commit()



   def delete_share(self,id):
      """ Delete single share represented by id.
      """
      
      cur = self.db.cursor()
      
      logger = cernbox_utils.script.getLogger('db')

      sql="DELETE FROM oc_share WHERE id=%d;"%int(id)
      
      logger.debug(sql) # FIXME: debug?
      cur.execute(sql)
      self.db.commit()

      # Check referential integrity.      
      # insert into oc_share(share_type, share_with, uid_owner, parent, item_type, item_source, item_target, file_source, file_target, permissions, stime) values (0,"rosma","cmsgemhw",NULL, "folder",28284090, "/28284090", 28284090, "/GE11_Shared_Documents (#28284090)",1,1489496970);


# Federated Sharing: External shares
   def insert_external_share(self,remote,remote_id,share_token,password,name,owner,user):
      """ Add an external share.
      """

      cur = self.db.cursor()

      logger = cernbox_utils.script.getLogger('db')

      mountpoint = "{{TemporaryMountPointName#%s}}"%name
      mountpoint_hash = md5_digest(mountpoint)

      remote_id = int(remote_id)

      sql = 'INSERT INTO oc_share_external(remote, remote_id, share_token, password, name, owner, user, mountpoint, mountpoint_hash, accepted) values (%s,%d,%s,%s,%s,%s,%s,%s,%s,%d);' % (quote(remote), remote_id, quote(share_token), quote(password), quote(name), quote(owner), quote(user), quote(mountpoint), quote(mountpoint_hash), 0)

      logger.debug(sql)
      cur.execute(sql)
      self.db.commit()



   def accept_external_share(self,id,mountpoint=None):
      """ Accept an external share and set its final mount point.
      """

      cur = self.db.cursor()
      logger = cernbox_utils.script.getLogger('db')

      set_cmd = []

      set_cmd.append("accepted = 1")

      if mountpoint:
         mountpoint_hash = md5_digest(mountpoint)
         set_cmd.append("mountpoint = '%s'"%mountpoint)
         set_cmd.append("mountpoint_hash = '%s'"%mountpoint_hash)

      set_cmd = ",".join(set_cmd)

      sql="UPDATE oc_share_external SET %s WHERE id=%d;"%(set_cmd,id)

      logger.debug(sql)
      cur.execute(sql)
      self.db.commit()



   def delete_external_share(self,id):
      """ Delete an external share.
      """

      cur = self.db.cursor()
      logger = cernbox_utils.script.getLogger('db')

      sql = 'DELETE FROM oc_share_external WHERE id=%d;'%int(id)

      logger.debug(sql)
      cur.execute(sql)
      self.db.commit()



   def get_external_share(self,remote=None,name=None,owner=None,user=None,accepted=None):
      """ Get detailed information on one share
          or the entire list of shares for one local user or a remote server//owner
      """
      cur = self.db.cursor()

      WHERE = []

      if remote:
         WHERE.append('remote = "%s"'%remote)

      if name:
         WHERE.append('name = "%s"'%name)

      if owner:
         WHERE.append('owner = "%s"'%owner)

      if user:
         WHERE.append('user = "%s"'%user)

      if accepted:
         WHERE.append('accepted = "%d"'%accepted)

      if WHERE:
         WHERE = "WHERE " + (' and '.join(WHERE))
      else:
         WHERE = ""

      logger = cernbox_utils.script.getLogger('db')

      sql = "SELECT * FROM oc_share_external "+WHERE
      logger.debug(sql)

      cur.execute(sql)

      external_shares = []
      for row in cur.fetchall():
         s = ExternalSharesInfo()
         for i,name in enumerate(ExternalSharesInfo._names):
            setattr(s,name,row[i])
         external_shares.append(s)
         logger.debug("ROW: %s",row)

      return external_shares



# Federated Sharing: Trusted servers
   def add_trusted_server(self,url):
      """ Add a server to the list of trusted ones.
      """

      cur = self.db.cursor()

      logger = cernbox_utils.script.getLogger('db')

      #TODO: CRITICAL
      #TODO: Understand how to set these values:
      url_hash = "hash_%s"%(url)
      token = "none"
      shared_secret = "none"
      status = 2
      sync_token = "none"
      status = int(status)

      #sql = 'INSERT INTO oc_trusted_servers(url, url_hash, token, shared_secret, status, sync_token) values (%s,%s,%s,%s,%d,%s)' % (url, url_hash, token, shared_secret, status, sync_token)
      sql = 'INSERT INTO oc_trusted_servers(url, url_hash, token, shared_secret, status, sync_token) values (%s,%s,%s,NULL,%d,NULL);' % (quote(url), quote(url_hash), quote(token), status)

      logger.debug(sql)
      cur.execute(sql)
      self.db.commit()



   def remove_trusted_server(self,id):
      """ Remove a server from the list of trusted ones represented by id.
      """

      cur = self.db.cursor()

      logger = cernbox_utils.script.getLogger('db')

      sql = 'DELETE FROM oc_trusted_servers WHERE id=%d;'%int(id)

      logger.debug(sql)
      cur.execute(sql)
      self.db.commit()



   def get_trusted_server(self,url=None):
      """ Get detailed information on one trusted server 
          or the entire list list of trusted servers for federated shares.
      """

      cur = self.db.cursor()

      WHERE = []

      if url:
         WHERE.append('url = "%s"'%url)

      if WHERE:
         WHERE = "WHERE " + (' and '.join(WHERE))
      else:
         WHERE = ""

      logger = cernbox_utils.script.getLogger('db')

      sql = "SELECT * FROM oc_trusted_servers "+WHERE
      logger.debug(sql)

      cur.execute(sql)

      trusted_servers = []
      for row in cur.fetchall():
         s = TrustedServersInfo()
         for i,name in enumerate(TrustedServersInfo._names):
            setattr(s,name,row[i])
         trusted_servers.append(s)
         logger.debug("ROW: %s",row)

      return trusted_servers


