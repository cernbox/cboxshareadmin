import cernbox_utils.script
import os

from cernbox_utils.eos import is_special_folder

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


      #db = db.ShareDB()

      shares=db.get_share(owner=args.shares_owner,share_type="regular")

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
            f=eos.fileinfo("inode:"+fid)

            if f.file.startswith(config['eos_recycle_dir']):
               # eos entry is in the trashbin
               logger.error("TRASHBIN_SHARE id=%d owner=%s sharee=%s target='%s' fid=%s",s.id,s.uid_owner,s.share_with,s.file_target,fid)
               logger.error("FIX: DELETE %s",s)
               if args.fix:
                  db.delete_share(s.id)
               continue
         except subprocess.CalledProcessError,x:
            if x.returncode == 2:
               # eos entry does not exist
               logger.error("DANGLING_SHARE id=%d owner=%s sharee=%s target='%s' fid=%s",s.id,s.uid_owner,s.share_with,s.file_target,fid)
               logger.error("FIX: DELETE %s",s)
               if args.fix:
                  db.delete_share(s.id)
               continue

         # share pointing outside of the home directories area
         # we do not validate these spaces later so we do not add these for subsequent verification
         if not os.path.normpath(f.file).startswith(config['eos_prefix']) and not os.path.normpath(f.file).startswith(config['eos_project_prefix']):
            logger.critical("OUTSIDE_SHARE share %s %s is outside of %s (%s)",s.id,s.file_target,config['eos_prefix'],f.file)
            #continue

         # NOT-AT-TOP-LEVELE SHARES ARE OK
         #if len(os.path.normpath(f.file).split("/"))>6:
         #   logger.error("NOT_AT_TOP_LEVEL_SHARE id=%d owner=%s sharee=%s target='%s' fid=%s actual_path=%s",s.id,s.uid_owner,s.share_with,s.file_target,fid,quote(f.file))
         #else:
 

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

            # keep the share with stronger permissions or prefer a newer one
            #if perm2 == 'rwx+d' or (perm2 == perm1 == 'rx'):
            #   logger.error("FIX1: (older) DELETE %s",existing_share)
            #   if args.fix:
            #      db.delete_share(existing_share.id)
            #   unique_share_keys[unique_key] = s
            #else:
            #   logger.error("FIX1:  (weaker) DELETE %s",s)
            #   if args.fix:
            #      db.delete_share(s.id)


            # check the actual ACL on eos (if exists) and stick to this one
            # eos_acls = eos.parse_sysacl(f.xattr['sys.acl'])

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

         #if not s.file_target.startswith("/") or s.file_target.count("/")>1:

         # check if owner still exists, if not issue error but treat the share normally
         # otherwise this is dangerous if local password database is not fully synchronized with ldap!
         try:
            pwd.getpwnam(s.uid_owner)
         except:
            logger.error("USER_NOT_FOUND: share owner uid %s does not exist",s.uid_owner)
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

         if args.homedir:
            homedir = args.homedir
         else:
           homedir = os.path.join(config['eos_prefix'],args.shares_owner[0],args.shares_owner)
            #homedir = '/eos/project/c/cmsgem-ge11-production'
            #homedir = '/eos/project/a/atlasweb'


         cnt = 0
         cnt_fix = 0
         cnt_safe_fix = 0
         cnt_unsafe_fix = 0
         cnt_wrong_bits = 0
         cnt_skipped = 0

         cnt_fix_plaindir = 0

         for f in eos.fileinfo_r(homedir,type="-d"):
            cnt += 1
            try:
               eos_acls = eos.parse_sysacl(f.xattr['sys.acl'])

               # in the rest of this algorithm below we assume that ACL bits belong to a known set
               # modify with care...
               ALLOWED_ACLS = ['rx','rwx+d','rwx!m']

               def check_allowed():
                  for a in eos_acls:
                     if not a.bits in ALLOWED_ACLS:
                        logger.fatal("ACL bits not allowed: %s %s %s",a, f.file, eos.dump_sysacl(eos_acls))
                        return False
                  return True

               if not check_allowed():
                  cnt_wrong_bits += 1
                  cnt_skipped += 1
                  continue

               if is_special_folder(f.file):
                  logger.error("Special folder should not have sys.acl set: %s",f.file)
                  # FIXME: remove ACL from special folder?
            except KeyError,x:
               if is_special_folder(f.file):
                  continue # skip this entry, it is okey for special folders not to have ACL at all
               else:
                  eos_acls = [] # no ACLs defined for this directory


            # FIX: u:wwweos:rx

            # BLACKLIST FUNCTIONALITY
            # do not touch anything in blacklisted paths: we may not know what to do with them (yet)
            def is_blacklisted(path):
               for black_p in blacklist_paths:
                  if f.file.startswith(black_p):
                     return True
               return False

            if is_blacklisted(f.file):
               cnt_skipped += 1
               continue

            # expected ACL
            expected_acls = [eos.AclEntry(entity="u",name=args.shares_owner,bits="rwx!m")] # this acl entry should be always set for every directory in homedir
            p = os.path.normpath(f.file)
            
            assert(f.is_dir())
            
            p += "/" # add trailing slash to directories, this will make sure that the top-of-shared-directory-tree also matches 

            shared_directory = False # indicate if the current directory is shared

            for sp in shared_paths:
               if p.startswith(sp): # directory is part of a share tree which has a top at sp
                  expected_acls.extend(shared_acls[sp])
                  shared_directory = True

            expected_acls = cernbox_utils.sharing.squash(set(expected_acls))

            logger.debug(" --- SCAN      --- %s --- %s --- %s",f.fid, f.file, eos.dump_sysacl(eos_acls))

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

               logger.error("FIX_ACL%s: %s '%s' %s", msg, f.fid, f.file, " ".join([a[0]+" "+eos.dump_sysacl(a[1]) for a in actions]))

               eos_master.set_sysacl(f.file,eos.dump_sysacl(expected_acls),dryrun=dryrun)

            else:
               pass

         logger.critical("Overview for user %s : scanned %d directories, safe fix: %d unsafe fix: %d plaindir fix: %d skipped: %d wrong bits: %d",args.shares_owner,cnt,cnt_safe_fix,cnt_unsafe_fix,cnt_fix_plaindir,cnt_skipped,cnt_wrong_bits)
            
      return 

      # compare the acl list calculated from share db with the actual acl list on eos in the shared directory tree
 
      for fid in shared_fids:

         f=eos.fileinfo("inode:"+fid)

         db_acls = set(shared_fids[fid])

         # add the ACL for the owner
         try:
            owner = pwd.getpwuid(int(f.uid)).pw_name
         except KeyError,x:
            logger.error("USER_NOT_FOUND: file owner uid %s does not exist, skipping... %s",f.uid,f.file)
            continue

         db_acls.add(eos.AclEntry(entity='u',name=owner,bits='rwx!m'))

         # here we recursively check if the same set of db_acls is consistenly applied in the whole tree
         # the first entry reported is the shared directory itself (the top level of the tree)
         # we will need maybe to prune bottom paths to avoid too many error messages for large trees
         for f in eos.fileinfo_r(f.file,type="-d"):
            if not is_special_folder(f.file):
               logger.debug("checking shared tree: %s",str(f.file))
               eos_acls = set(eos.parse_sysacl(f.xattr['sys.acl']))

               extra_acls = eos_acls-db_acls
               if extra_acls:
                  logger.warning("EXTRA_ACL path '%s': %s owner: %s ACTUAL %s EXPECTED %s",f.file,eos.dump_sysacl(cernbox_utils.sharing.squash(extra_acls)),owner,f.xattr['sys.acl'], eos.dump_sysacl(cernbox_utils.sharing.squash(db_acls)))

               missing_acls = db_acls-eos_acls
               if missing_acls:
                  logger.error("MISSING_ACL path '%s': %s owner: %s ACTUAL %s EXPECTED %s",f.file,missing_acls,owner,f.xattr['sys.acl'], eos.dump_sysacl(cernbox_utils.sharing.squash(db_acls)))
                  break
      logger.info('verified %d shares and %d eos paths'%(len(shares),len(shared_fids)))
   
      logger.info("OK")
