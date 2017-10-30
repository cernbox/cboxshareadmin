import cernbox_utils.script

class ShareInfo(cernbox_utils.script.Data):
   _names = ['id','share_type','share_with','uid_owner','uid_initiator','parent','item_type','item_source','item_target','file_source','file_target','permissions','stime','accepted','expiration','token','mail_send']


   def _check_consistency(self):
      pass

import MySQLdb


# mapping: column_name => index
#oc_share = dict([(name,i) for i,name in enumerate(['id','share_type','share_with','uid_owner','parent','item_source','item_target','file_source','file_target','permissions','stime','accepted','expiration','token','mail_send'])])



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

   def insert_folder_share(self,owner,sharee,fid,file_target,permissions,stime=None):
      cur = self.db.cursor()
      logger = cernbox_utils.script.getLogger('db')

      assert(all(c.isalnum() for c in owner))
      assert(all(c.isalnum() or c=='-' for c in sharee)) # egroups may have dash in the name

      if '-' in sharee:
         share_type = 1 # group
      else:
         share_type = 0 # user

      assert(fid>0)
      assert(permissions>=0)
      assert(stime is None or stime>0)
      assert(file_target!="")

      def quote(x):
         return '"'+x+'"'
      
      item_source=fid
      item_target=quote("/%d"%fid)
      file_source=fid
      file_target=quote(file_target)
      
      if stime is None:
         import time
         stime = time.time()


      sql = 'INSERT INTO oc_share(share_type, share_with, uid_owner, parent, item_type, item_source, item_target, file_source, file_target, permissions, stime) values (%d,%s,%s,NULL,"folder",%d,%s,%d,%s,%d,%d)' % (share_type,quote(sharee),quote(owner),item_source,item_target,file_source,file_target,permissions,stime);

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
