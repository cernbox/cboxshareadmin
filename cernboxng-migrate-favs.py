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

db_table = 'cbox_metadata' # this is will be the output table
admin_role=[0,0]

def main():
   global config,logger,eos_user

   import cernbox_utils.script

   parser=cernbox_utils.script.arg_parser(description='Migrate favorites ')
   parser.add_argument("--incremental", "-i", action='store_true', help="incremental migration: skip already migrated items")
   parser.add_argument("step", help="migration step: 1 or 2")
   parser.set_defaults(configfile="/etc/cboxshareadmin.migration.ini", logfile="/var/log/cernboxng-migrate-favs.log")
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

   t0 = time.time()

   query = ( "select uid,objid from oc_vcategory INNER JOIN oc_vcategory_to_object ON oc_vcategory.id=oc_vcategory_to_object.categoryid" )

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
   for fav_info in results:
           i+=1
           if i%100 == 1:
              print "Processed %d favs"%i

           uid,objid = fav_info

           logger.debug("Processing fav:" + str(fav_info))

           try:
              f = eos_user.fileinfo("inode:"+str(objid))

              if f.is_dir():
                 item_type = 0
              else:
                 item_type = 1 

              orphan=False

              if f.file.startswith('/eos/user/proc/recycle'):
                 orphan=True
              elif f.file.startswith('/eos/user/'):
                 if not f.file.startswith('/eos/user/%s/%s'%(uid[0],uid)):
                    logger.error("Skipping favourite in another's users home directory: %s %s",fav_info,f.file)
                    orphan=True
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
              continue

           insert_fav = ( "insert into " + db_table + " (id,item_type,uid,fileid_prefix,fileid,tag_key) VALUES(NULL,%d,'%s','%s',%d,'fav')"%(item_type,uid,fileid_prefix,objid))
           logger.debug(insert_fav)

           cursor.execute(insert_fav)

   print "Processed %d favs - done"%i

def migrate2(results,cursor):
   logger.error("Not implemented")

main()

