import cernbox_utils.script
from cernbox_utils.ns_inspect import NSInspect
import os
import subprocess
import re

from cernbox_utils.eos import is_special_folder
from .script import get_eos_server_string, get_eos_server

logger = cernbox_utils.script.getLogger('cmd')

def quote(s):
   if not s:
      s=''
   return "'"+s+"'"

def verify(args,config,eos,db):

      import pwd

      if not args.shares_owner.strip():
         logger.critical("Must provide a shares_owner or '-'")
         return

      if args.shares_owner == '-':
         args.shares_owner = ''

      if args.deep_fs_check:
         if not args.shares_owner:
            logger.critical("Must provide a single shares_owner for --deep-fs-check option")
            return

      if args.logdir:
         import logging
         fix_str = ""
         if args.fix: fix_str=".fix"
         logfn = os.path.join(args.logdir,"verify."+args.shares_owner+fix_str+".log")
         fh = logging.FileHandler(logfn)
         fh.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
         logger.addHandler(fh)

      shares=db.get_share(owner=args.shares_owner,share_type="regular",orphans=args.orphans)

      # if needed this can be used to split read from write traffic in order not to overload the instance

      # for write ops
      #eos_master = eos.EOS(config['eos_mgm_url'])
      #eos_master.role=(0,0)

      # for read ops
      #eos = eos.EOS(config['eos_slave_mgm_url'])
      #eos.role=(0,0)

      eos_master=eos

      # calculate complete acl list for each shared eos path (fid)
      # verify if shares are not outdated
   
      shared_fids = {}

      # shared_paths: key is a path with a trailing slash 
      shared_paths = {}
      shared_acls = {}

      # detect duplicate shares
      unique_share_keys = {}

      #parent_paths = {}

      disable_deep_check = False

      logger.info('Found %d shares of user %s',len(shares),args.shares_owner)

      for s in shares:
         fid = s.item_source

         logger.debug("Processing share: %s %s->%s %s %s",s.id,s.uid_owner,s.share_with,s.item_source,quote(s.file_target))

         # Verify if share points to a valid storage entity
         try:
            # If the user shared from projects, we need to go to the respective EOS instance,
            # so we cannot assume (and always use) the user EOS instance.
            eos_to_check = cernbox_utils.eos.EOS(get_eos_server_string(s.fileid_prefix))
            eos_to_check.role=(0,0)
            f=eos_to_check.fileinfo("inode:"+fid)

            if re.match(config['eos_recycle_dir'], f.file):
               # eos entry is in the trashbin
               logger.error("TRASHBIN_SHARE id=%d owner=%s sharee=%s target='%s' fid=%s",s.id,s.uid_owner,s.share_with,s.file_target,fid)
               logger.error("FIX: SET_ORPHAN %s",s)
               if args.fix:
                  db.set_orphan(s.id)
               continue
         except subprocess.CalledProcessError,x:
            if x.returncode == 2:
               # eos entry does not exist
               logger.error("DANGLING_SHARE id=%d owner=%s sharee=%s target='%s' fid=%s",s.id,s.uid_owner,s.share_with,s.file_target,fid)
               logger.error("FIX: SET_ORPHAN %s",s)
               if args.fix:
                  db.set_orphan(s.id)
               continue

         # share pointing outside of the home directories area
         # we do not validate these spaces later so we do not add these for subsequent verification
         if not os.path.normpath(f.file).startswith(config['eos_prefix']) and not os.path.normpath(f.file).startswith(config['eos_project_prefix']):
            logger.critical("OUTSIDE_SHARE share %s %s is outside of %s (%s)",s.id,s.file_target,config['eos_prefix'],f.file)
            #continue

         # Verify duplicate shares

         unique_key = (fid,s.share_with,s.uid_owner)

         try:
            existing_share = unique_share_keys[unique_key]
          
            perm1 = cernbox_utils.sharing.share2acl(existing_share).bits # older (shares are sorted by sid which grows in time)
            perm2 = cernbox_utils.sharing.share2acl(s).bits # newer (current)


            logger.error("DUPLICATE_SHARE older_share: id1 %s perm1 %s stime1 %s; newer_share: id2 %d perm2 %s stime2 %s (owner=%s sharee=%s target='%s' fid=%s)",existing_share.id,perm1,existing_share.stime,s.id,perm2,s.stime,s.uid_owner,s.share_with,s.file_target,fid)

            assert(perm1 in ['rx','rwx+d']) #we don't understand other permissions
            assert(perm2 in ['rx','rwx+d']) #we don't understand other permissions

            # here there may be multiple strategies how to fix duplicates

            # exact duplicates are safe to remove
            if perm1 == perm2:
               logger.error("FIX: exact duplicates, will delete older share: %s",existing_share.id)
               if args.fix:
                  db.delete_share(existing_share.id)
                  unique_share_keys[unique_key] = s                  
            else:
               logger.error("duplicate share with different permissions, delete manually one of: %s %s",existing_share.id,s.id)
               disable_deep_check = True

            continue

         except KeyError:
            unique_share_keys[unique_key] = s

         if s.file_target.count("/")>1:
            logger.error("FILE_TARGET_MULTIPLE_SLASH_PROBLEM id=%d owner=%s sharee=%s target='%s' fid=%s stime=%s",s.id,s.uid_owner,s.share_with,s.file_target,fid,s.stime)
            fixed_target='/%s'%os.path.basename(s.file_target)
            assert("'" not in fixed_target)
            logger.error("FIX: update target to '%s'",fixed_target)
            if args.fix:
               db.update_share(s.id,file_target=fixed_target)
            continue

         # check if owner still exists, if not issue error but treat the share normally
         # otherwise this is dangerous if local password database is not fully synchronized with ldap!
         try:
            pwd.getpwnam(s.uid_owner)
         except:
            logger.error("USER_NOT_FOUND: share owner uid %s does not exist",s.uid_owner)
            logger.error("FIX: SET_ORPHAN %s",s)
            if args.fix:
               db.set_orphan(s.id)
            continue

         if s.share_type == 1:
            logger.info("Share type 1 (egroup). Not checking if destination exists")
         else:
            try:
               pwd.getpwnam(s.share_with)
            except:
               logger.error("USER_NOT_FOUND: share destination uid %s does not exist",s.share_with)
               logger.error("FIX: SET_ORPHAN %s",s)
               if args.fix:
                  db.set_orphan(s.id)
               continue

         logger.info("VALID_SHARE: share_id=%s %s->%s %s %s %s",s.id,s.uid_owner,s.share_with,s.item_source,quote(s.file_target),quote(f.file))
         
         # this is the expected ACL entry in the shared directory tree
         acl = cernbox_utils.sharing.share2acl(s)

         shared_fids.setdefault(fid,[]).append(acl)

         p = os.path.normpath(f.file)+"/" # append trailing slash, otherwise directories which basename is a substring give false positive, e.g.: /eos/user/k/kuba/tmp.readonly /eos/user/k/kuba/tmp
         shared_paths[p] = fid
         shared_acls.setdefault(p,[]).append(acl)
         

      logger.info("Expected shared paths with visibility to others (%s)",len(shared_acls))
      for p,acl in shared_acls.items():
         logger.info("Expected acls in shared path %s %s",p,eos.dump_sysacl(acl))

      blacklist_paths=[]
      # BLACKLIST FUNCTIONALITY
      logger.info("Blacklisted trees (%s) which will not be analysed but are problematic",len(blacklist_paths))
      for p in blacklist_paths:
         logger.error("Blacklisted %s",p)

         
      # scan full tree

      if args.deep_fs_check:

         if disable_deep_check:
            logger.fatal("deep check disabled by previous errors")
            return

         if args.project_name:
            homedir = os.path.join(config['eos_project_prefix'],args.project_name[0],args.project_name)
            eos_to_check = cernbox_utils.eos.EOS(get_eos_server(args.project_name, 'project'))

         elif args.homedir:
            # homedir = args.homedir
            raise Exception("Manual path not supported atm")
            
         else:
            homedir = os.path.join(config['eos_prefix'],args.shares_owner[0],args.shares_owner)
            eos_to_check = cernbox_utils.eos.EOS(get_eos_server(args.shares_owner))

         eos_to_check.role=(0,0)
         logger.info("Using EOS MGM: %s" % eos_to_check.mgmurl)

         cnt = 0
         cnt_fix = 0
         cnt_safe_fix = 0
         cnt_unsafe_fix = 0
         cnt_wrong_bits = 0
         cnt_skipped = 0

         cnt_fix_plaindir = 0

         ns = NSInspect(config, logger)

         for (file, acls, cid) in ns.inspect(homedir):
            cnt += 1
            try:
               eos_acls = eos.parse_sysacl(acls)

               # in the rest of this algorithm below we assume that ACL bits belong to a known set
               # modify with care...
               ALLOWED_ACLS = ['rx','rwx+d','rwx']

               def check_allowed():
                  for a in eos_acls:
                     if not a.bits in ALLOWED_ACLS:
                        logger.fatal("ACL bits not allowed: %s %s %s",a, file, eos.dump_sysacl(eos_acls))
                        return False
                  return True

               if not check_allowed():
                  cnt_wrong_bits += 1
                  cnt_skipped += 1
                  continue

               if is_special_folder(file):
                  logger.error("Special folder should not have sys.acl set: %s",file)
                  # FIXME: remove ACL from special folder?
                  cnt_skipped += 1
                  continue
            except KeyError,x:
               if is_special_folder(file):
                  continue # skip this entry, it is okey for special folders not to have ACL at all
               else:
                  eos_acls = [] # no ACLs defined for this directory


            # FIX: u:wwweos:rx

            # BLACKLIST FUNCTIONALITY
            # do not touch anything in blacklisted paths: we may not know what to do with them (yet)
            def is_blacklisted(path):
               for black_p in blacklist_paths:
                  if file.startswith(black_p):
                     return True
               return False

            if is_blacklisted(file):
               cnt_skipped += 1
               continue

            # expected ACL
            uid = str(pwd.getpwnam(args.shares_owner).pw_uid)
            expected_acls = [eos.AclEntry(entity="u",name=uid,bits="rwx")] # this acl entry should be always set for every directory in homedir

            p = os.path.normpath(file)

            if args.project_name:
               expected_acls += [eos.AclEntry(entity="egroup",name='cernbox-project-%s-writers'%args.project_name, bits="rwx+d"),
                                 eos.AclEntry(entity="egroup",name='cernbox-project-%s-readers'%args.project_name, bits="rx")]


               if p.startswith(os.path.join(homedir,'www')):
                  expected_acls += [eos.AclEntry(entity="u",name='83367',bits='rx')] # uid wwweos
            
            p += "/" # add trailing slash to directories, this will make sure that the top-of-shared-directory-tree also matches 

            shared_directory = False # indicate if the current directory is shared

            for sp in shared_paths:
               if p.startswith(sp): # directory is part of a share tree which has a top at sp
                  expected_acls.extend(shared_acls[sp])
                  shared_directory = True

            expected_acls = cernbox_utils.sharing.squashAcls(expected_acls)

            logger.debug(" --- SCAN      --- (cid:%s) %s --- %s", cid, file, eos.dump_sysacl(eos_acls))

            dryrun = not args.fix

            actions = []
            safe_fix = None # determines if it is "safe" to fix the ACLs (not taking away existing permissions)

            if set(eos_acls) < set(expected_acls):
               actions.append(("ADD",set(expected_acls)-set(eos_acls)))
               safe_fix = True
            elif set(eos_acls) > set(expected_acls):
               actions.append(("REMOVE",set(eos_acls)-set(expected_acls)))
               safe_fix = False
            elif set(eos_acls) != set(expected_acls):
                  if not args.fix_all_perms:
                     dryrun = True # do not fix anything like that (unless explicitly specified: --fix-all-perms)

                  safe_fix = False

                  # let's be a bit more specific about the differences

                  added_acls = set(expected_acls)-set(eos_acls)
                  removed_acls = set(eos_acls)-set(expected_acls)

                  updated_acls = set()

                  def find_acl_by_entity_name(entity,name,acl_list):
                     for a in acl_list:
                        if a.entity == entity and a.name == name:
                           return a
                     return None

                  for acl1 in removed_acls.copy(): # we may remove from removed_acls set as we iterate over it

                     acl2 = find_acl_by_entity_name(acl1.entity,acl1.name,added_acls)

                     if acl2:

                        if 'rx' in acl1.bits:
                           safe_fix = True

                        updated_acls.add(eos.AclEntry(entity=acl1.entity,name=acl1.name,bits=acl1.bits+"->"+acl2.bits))
                        removed_acls.remove(acl1)
                        added_acls.remove(acl2)


                  if added_acls:
                     actions.append(("ADD",added_acls))
                  if removed_acls:
                     actions.append(("REMOVE",removed_acls))
                  if updated_acls:
                     actions.append(("UPDATE",updated_acls))
                  
            if actions:

               cnt_fix += 1

               if not shared_directory:
                  cnt_fix_plaindir += 1

               if safe_fix:
                  msg = "_SAFE"
                  cnt_safe_fix +=1
               else:
                  msg = ""
                  cnt_unsafe_fix +=1

               logger.error("FIX_ACL%s: %s %s", msg, file, " ".join([a[0]+" "+eos.dump_sysacl(a[1]) for a in actions]))

               eos_to_check.set_sysacl('pid:%s'%cid, eos_to_check.dump_sysacl(expected_acls), dryrun=dryrun)

            else:
               pass

         logger.critical("Overview for user %s : scanned %d directories, safe fix: %d unsafe fix: %d plaindir fix: %d skipped: %d wrong bits: %d",args.shares_owner,cnt,cnt_safe_fix,cnt_unsafe_fix,cnt_fix_plaindir,cnt_skipped,cnt_wrong_bits)
            
      return 

def remove_orphan_xbits(args,config,eos,db):
      logfn = ""

      if args.logdir:
         import logging
         fix_str = ""
         if args.fix: fix_str=".fix"
         logfn = os.path.join(args.logdir,os.path.normpath(args.path).replace(os.sep,"_")+fix_str+".log")
         fh = logging.FileHandler(logfn)
         fh.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
         logger.addHandler(fh)

      cnt = 0
      fixed_cnt = 0

      for f in eos.fileinfo_r(args.path,type="-d"):
         cnt += 1
         try:
            eos_acls = eos.parse_sysacl(f.xattr['sys.acl'])
         except KeyError,x:
            continue # no ACL at all

         new_acls = []
         for acl in eos_acls:
            if not acl.bits == "x":
               new_acls.append(acl)

         #logger.info(" --- SCAN      --- %s --- %s --- %s",f.fid, f.file, eos.dump_sysacl(eos_acls))

         if new_acls != eos_acls:
            logger.info(" --- NEW_ACL   --- %s --- %s --- %s --- %s",f.fid, f.file, eos.dump_sysacl(new_acls),eos.dump_sysacl(eos_acls))
            eos.set_sysacl(f.file,eos.dump_sysacl(new_acls),dryrun=not args.fix)
            fixed_cnt += 1
         else:
            #logger.info(" --- NO_CHANGE --- %s --- %s --- %s",f.fid, f.file, eos.dump_sysacl(eos_acls))
            pass

      logger.info("Scanned %d directories, fixed %d directories, logfile: %s",cnt,fixed_cnt,logfn)


def summary(args,config,eos,db):

      from cernbox_utils import db,eos

      if not args.shares_owner.strip():
         logger.critical("Must provide a shares_owner or '-'")
         return

      if args.shares_owner == '-':
         args.shares_owner = ''


      db = db.ShareDB()

      shares=db.get_share(owner=args.shares_owner)

      owner_all_share_cnt = {}
      owner_link_share_cnt = {}
      owner_regular_share_cnt = {}

      for s in shares:
         try:
            if s.file_target is None:
               s.file_target = ''

            logger.debug("Processing share: %s %s->%s %s %s",s.id,s.uid_owner,s.share_with,s.item_source,quote(s.file_target))

            owner_all_share_cnt.setdefault(s.uid_owner,0)
            owner_link_share_cnt.setdefault(s.uid_owner,0)
            owner_regular_share_cnt.setdefault(s.uid_owner,0)

            owner_all_share_cnt[s.uid_owner] += 1

            if s.share_type == 3:
               owner_link_share_cnt[s.uid_owner] += 1
            else:
               owner_regular_share_cnt[s.uid_owner] += 1

         except Exception,x:
            logger.error("Problem with processing share id=%d : %s",s.id,repr(x))
            raise

      sort_by = owner_all_share_cnt


      if args.sort_by == 'regular':
         sort_by = owner_regular_share_cnt

      if args.sort_by == 'link':
         sort_by = owner_link_share_cnt

      index = len(owner_all_share_cnt)

      for u,cnt in sorted(sort_by.iteritems(), key=lambda (k,v): (v,k)):
         logger.info("Index #%4d Owner %10s has total of %4d shares: %4d regular shares, %4d link shares",index,u,owner_all_share_cnt[u],owner_regular_share_cnt[u],owner_link_share_cnt[u])
         index -= 1


def show_other_acl(args,config,eos,db):

      other_acl_cnt = 0
      empty_acl_cnt = 0
      special_dir_cnt = 0
      cnt = 0

      for f in eos.fileinfo_r(args.path,type="-d"):

         cnt += 1
      
         if is_special_folder(f.file):
            special_dir_cnt+=1
            if args.ignore_special_directories:
               continue

         try:
            eos_acls = eos.parse_sysacl(f.xattr['sys.acl'])
         except KeyError,x:
            empty_acl_cnt+=1 # no ACL at all

         for acl in eos_acls:
            if acl.name != args.name:
               other_acl_cnt+=1
               logger.info("%s %s",f.file,eos_acls)
               break
            
      logger.info("Scan completed. Found %d directories, %d with acls not containing %s, %d with empty acls, %d special dirs",cnt,other_acl_cnt,args.name,empty_acl_cnt,special_dir_cnt)


def acl_update(args,config,eos,db):
      import cernbox_utils.sharing

      if args.pathspec.startswith("inode:"):
         inode = args.pathspec[len("inode:"):]
      else:
         inode = eos.fileinfo(args.pathspec).ino

      cernbox_utils.sharing.update_acls(inode,eos,db,owner=None,dryrun=False)
