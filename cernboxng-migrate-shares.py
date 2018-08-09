#!/usr/bin/env python
# ------------------------------------------------------------------------------
# File: migrate-shares-eoshome.py
# Author: Jakub Moscicki <jakub.moscicki@cern.ch>
# Author: Edward Karavakis <edward.karavakis@cern.ch>
# ------------------------------------------------------------------------------
#
# ******************************************************************************
# EOS - the CERN Disk Storage System
# CERNBOX - the CERN Cloud Data Storage System
# Copyright (C) 2018 CERN/Switzerland
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
# ******************************************************************************


# WARNING: if you get permission denied errors, do a kdestroy,
# somehow it interfers with the authentication mechanism of EOS.

# %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
# Perform internal setup of the environment.
# This is a Copy/Paste logic which must stay in THIS file
def standardSetup():
   import sys, os.path
   # insert the path to cernafs based on the relative position of this scrip inside the service directory tree
   exeDir = os.path.abspath(os.path.normpath(os.path.dirname(sys.argv[0])))
   pythonDir = os.path.join(exeDir, 'python' )
   sys.path.insert(0, pythonDir)
   import cernbox_utils.setup
   cernbox_utils.setup.standardSetup(sys.argv[0]) # execute a setup hook

standardSetup()
del standardSetup
# %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%


import MySQLdb
import sys, os, logging, subprocess, time
import cernbox_utils.eos

logger=None
config=None
eos_user=None

db_table = 'oc_share'
admin_role=[0,0]

def main():
   global config,logger,eos_user

   import cernbox_utils.script

   parser=cernbox_utils.script.arg_parser(description='Migrate shares ')
   parser.add_argument("--incremental", "-i", action='store_true', help="incremental migration: skip already migrated shares")
   parser.add_argument("step", help="migration step: 1 or 2")
   parser.add_argument("user", help="specify user (or - for all users)")
   parser.set_defaults(configfile="/etc/cboxshareadmin.migration.ini", logfile="/var/log/cernboxng-migrate-shares.log")
   parser.set_defaults(loglevel=logging.INFO)
   args = parser.parse_args()

   config = cernbox_utils.script.configure(args.configfile)
   logger = cernbox_utils.script.getLogger(level=args.loglevel,filename=args.logfile)

   if args.step not in ['1','2']:
      logger.error("Wrong migration step specified")
      return

   admin_role[0] = config.get('eos_admin_uid',0)
   admin_role[1] = config.get('eos_admin_gid',0)

   eos_user = cernbox_utils.eos.EOS('root://eosuser-slave.cern.ch')
   eos_user.role=admin_role
   eos_user.cmd_opts={'log_warning':False} # don't warn if file not found
   eos_user.env=None

   config['dbname']='cernboxng' # forcing NG database

   host = config['dbhost'].split(':')[0]
   try:
      port = int(config['dbhost'].split(':')[1])
   except IndexError:
      port = None

   def hide_password(config):
      c=config.copy()
      c['dbpassword']='***'
      return c

   logger.info("Start with args: %s %s ",str(args),hide_password(config))

   cnx = MySQLdb.connect(host=host,port=port,user=config['dbuser'],passwd=config['dbpassword'],db=config['dbname'])
   cursor = cnx.cursor()


   if args.incremental:
      WHERE=["fileid_prefix IS NULL"] # don't process already processed shares
   else:
      WHERE=[] # process all shares again

   if args.user!='-':
      WHERE.append("uid_owner = '%s'  "%args.user)

   if WHERE:
      WHERE="WHERE "+" AND ".join(WHERE)
   else:
      WHERE=""

   t0 = time.time()
   query = ( " select id,file_target, item_source,file_source,fileid_prefix,uid_owner,share_type,item_type from " + db_table + " " + WHERE )

   logger.debug(query)
   cursor.execute(query)

   results = cursor.fetchall()

   if args.step == '1':
      migrate1(results,cursor)

   if args.step == '2':
      migrate2(results,cursor)

   cnx.commit()
   cursor.close()
   cnx.close()
   print "Transaction committed"
   print "Logfile",args.logfile
   print "Runtime: %d s"%(time.time()-t0)

def migrate1(results,cursor):
   i=0
   for share_info in results:
           i+=1
           if i%1000 == 1:
              print "Processed %d shares"%i

           id, file_target, item_source, file_source, fileid_prefix, uid_owner,share_type, item_type = share_info

           logger.debug("Processing share:" + str(share_info))

           try:
              f = eos_user.fileinfo("inode:"+str(file_source))

              new_file_target = '/'+os.path.basename(f.file)
              orphan=False

              if f.file.startswith('/eos/user/proc/recycle'):
                 orphan=True

              if f.file.startswith('/eos/user/'):
                 fileid_prefix='oldhome'
              elif f.file.startswith('/eos/project/'):
                 fileid_prefix='oldproject'
              else:
                 logger.error("file target in unknown location %s: %s"%(f,share_info))
                 orphan=True

           except subprocess.CalledProcessError,x:
              if 'No such file or directory' in x.stderr:
                 orphan=True
              else:
                 logger.error("Processing %s: %s",share_info,repr(x.stderr))
                 continue

           if orphan:
               update_orphan = ( "update " + db_table + " set orphan = 1 where id = " + str(id) )
               cursor.execute(update_orphan)            
           else:
               update_prefix = ( " update " + db_table + " set orphan = 0, item_target = NULL, fileid_prefix = '" + fileid_prefix + "', file_target = \'" + MySQLdb.escape_string(new_file_target) + "\' where id = " + str(id) )
               cursor.execute(update_prefix)

               if share_type == 3:
                   if not new_file_target.startswith('/.sys.v#.') and item_type=='file':
                       print 'WARNING: file_target does not start with /.sys.v#.: ',id,new_file_target,file_source
                   share_name = new_file_target.replace('/.sys.v#.','')
                   share_name = share_name.strip('/') # remove slashes from both ends
                   cursor.execute( ("update oc_share set file_target = NULL, share_name = '%s' where id = %s"%( MySQLdb.escape_string(share_name),str(id))) )
   print "Processed %d shares - done"%i

def migrate2(results,cursor):
   i=0
   for share_info in results:
           i+=1
           if i%1000 == 1:
              print "Processed %d shares"%i

           id, file_target, item_source, file_source, fileid_prefix, uid_owner,share_type, item_type = share_info

           logger.debug("Processing share:" + str(share_info))

           try:
              f1 = eos_user.fileinfo("inode:"+str(file_source))
           except subprocess.CalledProcessError,x:
              if 'No such file or directory' in x.stderr:
                 continue # skip orphans 
              else:
                 logger.error("Processing %s: %s",share_info,repr(x.stderr))
                 continue

           eos_home = cernbox_utils.eos.EOS('root://eoshome-%s.cern.ch'%uid_owner[0])
           eos_home.role=admin_role #(72811,1028)
           eos_home.cmd_opts={'log_warning':False} # don't warn if file not found
           eos_home.env=None
            
           try:
              f2 = eos_home.fileinfo(f1.file.replace('/eos/user/.migrated/','/eos/user/',1)) # original homedir was moved to .migrated directory, so we need to remove that to get the correct path on eoshome
           except subprocess.CalledProcessError,x:
              if 'No such file or directory' in x.stderr:
                 logger.error("File %s does not exist in eoshome (but it exists in eosuser): %s",f1.file,str(f1))
                 continue
              else:
                 logger.error("Processing %s: %s",share_info,repr(x.stderr))
                 raise           

           update_prefix = ( " update " + db_table + " set fileid_prefix = 'eoshome-"+uid_owner[0]+"', file_source = \'" + f2.ino + "\' , item_source = \'" + f2.ino + "\' where id = " + str(id) )
           cursor.execute(update_prefix)

   print "Processed %d shares - done"%i

main()

