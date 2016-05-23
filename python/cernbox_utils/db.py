import cernbox_utils.script

class ShareInfo(cernbox_utils.script.Data):
   _names = ['id','share_type','share_with','uid_owner','parent','item_type','item_source','item_target','file_source','file_target','permissions','stime','accepted','expiration','token','mail_send']


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
      
   def get_share(self,fid=None,sharee=None,owner=None,share_type=None):
      """ Get share information matchin target file id AND sharee name AND owner name AND share type ("link" or "regular").
      """
      cur = self.db.cursor()

      WHERE = []

      if fid:
         WHERE.append('file_source = "%s"'%fid)

      if sharee:
         WHERE.append('share_with = "%s"'%sharee)

      if owner:
         WHERE.append('uid_owner = "%s"'%owner)

      if share_type:
         if share_type == "link": 
            WHERE.append('share_type = 3')

         if share_type == "regular": 
            WHERE.append('share_type != 3')

      if WHERE:
         WHERE = "WHERE " + (' and '.join(WHERE))

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

   
