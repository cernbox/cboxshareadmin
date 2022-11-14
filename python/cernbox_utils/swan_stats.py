import cernbox_utils.script
import re

from .script import get_eos_server_string

logger = cernbox_utils.script.getLogger('cmd')
import cernbox_utils.eos

def quote(s):
   if not s:
      s=''
   return "'"+s+"'"

def get_stats(db):

      shares=db.get_share(share_type='regular')

      logger.info('Found %d shares',len(shares))

      counter = 0
      paths = set()
      mappings = {}

      for s in shares:
         fid = s.item_source

         logger.debug("Processing share: %s %s->%s %s %s",s.id,s.uid_owner,s.share_with,s.item_source,quote(s.file_target))

         if s.fileid_prefix.startsWith('eosproject') or s.fileid_prefix.startsWith('newproject'):
            continue

         try:
            if s.fileid_prefix in mappings.keys():
               filename = mappings[s.fileid_prefix]
            else:
               eos_to_check = cernbox_utils.eos.EOS(get_eos_server_string(s.fileid_prefix))
               eos_to_check.role=(0,0)
               f=eos_to_check.fileinfo("inode:"+fid)
               filename = f.file
               mappings[s.fileid_prefix] = f.file

            share_string = 'NORMAL_SHARE'
            if re.match(r'/eos/user/[a-z]/([a-z0-9])+/SWAN_projects/.*', filename):
               counter += 1
               paths.add(filename)
               share_string = 'SWAN_SHARE'
            logger.info("%s id=%d owner=%s sharee=%s target='%s' fid=%s path='%s'",share_string, s.id,s.uid_owner,s.share_with,s.file_target,fid, filename)

         except:
               logger.error("Error analysing share id=%d owner=%s sharee=%s target='%s' fid=%s",s.id,s.uid_owner,s.share_with,s.file_target,fid)
  
      logger.info("TOTAL_SHARES n=%s, n_files_shared=%s",counter, len(paths))
      return
