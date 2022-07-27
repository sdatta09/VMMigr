#!/usr/bin/env python3

import os, sys, signal, argparse
import jinja2
from jinja2.utils import concat
import re
#import requests
import time
import base64
#import xmltodict
#import subprocess
import json
from pprint import pprint
from collections import OrderedDict, Counter
#import uuid
from pprint import pprint
import logging
import logging.handlers
import glbl
import common 

pyVer = sys.version_info
if pyVer.major == 3:
  import http.client as httplib 
else:
  import httplib


#import vnms
vnms =  None
analy = None 
cntlr = None
cust = None
admin = None
debug = 0
mlog = None
mdict = None

class bcolors:
  """ the background colors
  """
  HEADER = '\033[95m'
  OKBLUE = '\033[94m'
  OKGREEN = '\033[92m'
  OKCHECK = '\033[96m'
  OKWARN = '\033[93m'
  FAIL = '\033[91m'
  ENDC = '\033[0m'
  BOLD = '\033[1m'
  UNDERLINE = '\033[4m'


def argcheck():
  """ This performs adds the  argument and checks the requisite inputs
  """
  global args
  mystr = os.path.basename(sys.argv[0])
  parser = argparse.ArgumentParser(prog=os.path.basename(sys.argv[0]),description='%(prog)s Help:',usage='%(prog)s -f filename [options]', add_help=False)
  parser.add_argument('-f','--file',required=True, help='input file [required ]' )
  parser.add_argument('-d','--debug',default=0, help='set/unset debug flag')

  try:
    args = vars(parser.parse_args())
  except:
    usage()
    sys.exit(0)

def usage():
  mystr = os.path.basename(sys.argv[0])
  print(bcolors.OKCHECK)
  print( """\
Usage:
    To change versions use:
      %(mystr)s --f/-f <infile>
    To add more debug:
      %(mystr)s -f <infile> --debug/-d [0/1]
  """ %locals())
  print(bcolors.ENDC)

def json_loads(_str,**kwargs):
    global mlog
    try:
      _jstr = json.loads(_str,**kwargs)
      return _jstr
    except Exception as ex:
       mlog.error('Json load failed: {}'.format(ex))
       sys.exit('Json load failed: {}'.format(ex))



def get_default( _method, _uri,_payload,resp='200', ofile=None):
    global vnms, analy, cntlr, cust, mlog
    vdict = {}
    mlog.info("In function " + get_default.__name__)
    vdict = {'body': _payload, 'resp': resp, 'method': _method, 'uri': _uri}
    [out, resp_str] = common.call(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
    jstr = json_loads(resp_str)
    #print(jstr)
    if ofile is None: 
       mlog.error("No file provided .. exiting")
       sys.exit("No file provided .. exiting")
    out = common.create_out_data("POST","200","/vnms/sdwan/workflow/controllers/controller", jstr)
    fp=open(ofile,"w+")
    out1 = json.dumps(out, indent=4)
    fp.write(out1)
    fp.close()
    return

def deploy_controller( _method, _uri,_payload,resp='202',name="Controller"):
    global vnms, analy, cntlr, cust, mlog
    vdict = {}
    mlog.info("In function " + deploy_controller.__name__)
    vdict = {'body': _payload, 'resp': resp, 'method': _method, 'uri': _uri}
    common.call(vdict,content_type='json',ncs_cmd="no")
    # Now we need to check the status
    common.check_controller_status(name=name)
    return 

def process_diff(f1, f2):
    cnt1=Counter()
    for i in f1:
      cnt1[i] += 1
    cnt2=Counter()
    for i in f2:
      cnt2[i] += 1

    return list(cnt2-cnt1)

    

def get_backup( _method, _uri,_payload,resp='200',vd_data=None, option=2):
    resp2='202'
    vdict = {}
    #vdict = {'body': _payload, 'resp': resp, 'method': _method, 'uri': _uri}
    uri = "/api/config/system/_operations/recovery/list"
    payload = {}
    vdict1 = {'body': payload, 'resp': resp, 'resp2': resp2, 'method': "POST", 'uri': uri,
              'vd_ip' :  vd_data['vd_ip'], 'vd_rest_port': vd_data['vd_rest_port'],
               'auth': vd_data['auth'] }
    [out, resp_str] = common.newcall(vdict1,content_type='json',ncs_cmd="no",jsonflag=1)
    if len(resp_str) > 3 :
      recoverylist1 = json_loads(resp_str)
      if "output" in recoverylist1:
        if "files" in recoverylist1["output"]:
          file1 = [ i["name"] for i in recoverylist1["output"]["files"] ] 
        else:
          file1 = []
        # Now call the backup Api
        vdict = {'body': _payload, 'resp': resp, 'resp2': resp2, 'method':_method , 'uri': _uri,
                  'vd_ip' :  vd_data['vd_ip'], 'vd_rest_port': vd_data['vd_rest_port'],
                   'auth': vd_data['auth']
        }
        [out, resp_str] = common.newcall(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
        if len(resp_str) > 3 :
          backup = json_loads(resp_str)
          if "output" in  backup and "status" in backup["output"] and (backup["output"]["status"].find("initiated") != -1):
            for i in range(0,5):
              time.sleep(10)
              [out, resp_str] = common.newcall(vdict1,content_type='json',ncs_cmd="no",jsonflag=1)
              if len(resp_str) > 3 :
                recoverylist2 = json_loads(resp_str)
                if "output" in recoverylist2 and "files" in recoverylist2["output"]:
                  file2 = [ i["name"] for i in recoverylist2["output"]["files"] ] 
                  if len(file2) > len (file1):
                    diff_list = process_diff(file1, file2)
                    if len(diff_list) > 0:
                      diff_name = diff_list[0]
                      if option == 2: 
                        mlog.warn(bcolors.OKWARN +"Backup on New Director Created with Name={0} ".format(diff_name)+ bcolors.ENDC)
                      else: 
                        mlog.warn(bcolors.OKWARN +"Backup on Old Director Created with Name={0} ".format(diff_name)+ bcolors.ENDC)
                      return True
    if option == 2: 
      mlog.warn("Backup NOT created on New Director Name")
    else:
      mlog.warn("Backup NOT created on Old Director Name")
    return True
 

def get_dir_release_info( _method, _uri, _payload,resp='200', _name=None,vd_data=None,vd_data1=None,_ofile=None):
    global vnms, analy, cntlr, cust, admin, mlog
    mlog.info("In function {0} with outfile={1}".format(get_dir_release_info.__name__,_ofile))
    resp2 = '202'
    vdict = {}    
    vdict = {'body': _payload, 'resp': resp, 'resp2': resp2, 'method':_method , 'uri': _uri,
              'vd_ip' :  vd_data['vd_ip'], 'vd_rest_port': vd_data['vd_rest_port'],
              'auth': vd_data['auth'] }
    [out, resp_str] = common.newcall(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
 
    #vdict = {'body': _payload, 'resp': resp, 'resp2': resp2, 'method': _method, 'uri': _uri}
    #[out, resp_str] = common.call(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
    if len(resp_str) > 3:
      jstr = json_loads(resp_str)
      mlog.info("Release Info list = {0}".format(json.dumps(jstr,indent=4)))
      if "package-info" in jstr:
         if ("major-version" in jstr["package-info"][0] and "minor-version" in jstr["package-info"][0] 
                 and "service-version" in jstr["package-info"][0]):
           glbl.vnms.data["rel"] =  jstr["package-info"][0]["major-version"] + "." \
                                + jstr["package-info"][0]["minor-version"] + "." \
                                + jstr["package-info"][0]["service-version"] 
           org_data =  jstr["package-info"][0]["package-id"] 
           write_outfile(glbl.vnms,glbl.analy,glbl.cntlr,glbl.cust, glbl.admin)
           mlog.info("Wrote release information in output file ")
           if _ofile is None: 
             mlog.error("No file provided .. exiting")
             sys.exit("No file provided .. exiting")
           _str = '/api/operational/system/package-info?deep=true'
           newstr={}
           out = common.create_out_data("GET","200",_str,newstr)
           fp=open(_ofile,"w+")
           out1 = json.dumps(out, indent=4)
           fp.write(out1)
           fp.close()

      # Old Director
      vdict = {'body': _payload, 'resp': resp, 'resp2': resp2, 'method':_method , 'uri': _uri,
              'vd_ip' :  vd_data1['vd_ip'], 'vd_rest_port': vd_data1['vd_rest_port'],
              'auth': vd_data1['auth'] }
      [out, resp_str] = common.newcall(vdict,content_type='json',ncs_cmd="no",jsonflag=1)

      if len(resp_str) > 3:
        jstr = json_loads(resp_str)
        if "package-info" in jstr:
          if ("major-version" in jstr["package-info"][0] and "minor-version" in jstr["package-info"][0] 
                   and "service-version" in jstr["package-info"][0]):
            old_dir_pkg_info =   jstr["package-info"][0]["major-version"] + "." \
                                  + jstr["package-info"][0]["minor-version"] + "." \
                                  + jstr["package-info"][0]["service-version"]
            old_dir_pkg_id =   jstr["package-info"][0]["package-id"] 
            if glbl.vnms.data["rel"] ==  old_dir_pkg_info:
              mlog.info("Matched Package Info: {0}".format(glbl.vnms.data["rel"])) 
            else:
              mlog.error("Package Info dic not match New Director:{0} Old Director:{1}".format(glbl.vnms.data["rel"],old_dir_pkg_info)) 
            if org_data ==  old_dir_pkg_id:
              mlog.info("Matched Package ID: {0}".format(org_data))
            else:
              mlog.error("Package ID did not match. New Director:{0}== Old Director:{1}==".format(org_data,old_dir_pkg_id ))
      elif "error" in jstr and jstr["error"]['http_status_code'] == 401 :
        mlog.error("This is most likely a password issue. Please change in input json file: vm_phase2.json and re-run")
        sys.exit("This is most likely a password issue. Please change in input json file: vm_phase2.json and re-run")
    else:
      mlog.error("This is most likely a password issue. Please change in input file and re-run")
      sys.exit("This is most likely a password issue. Please change in input file and re-run")
    return ''

def get_dir_time_zones ( _method, _uri, _payload,resp='200', _name=None,_ofile=None):
    global vnms, analy, cntlr, cust, mlog
    mlog.info("In function {0} with outfile={1}".format(get_dir_time_zones.__name__,_ofile))
    resp2 = '202'
    vdict = {}
    vdict = {'body': _payload, 'resp': resp, 'resp2': resp2, 'method': _method, 'uri': _uri}
    [out, resp_str] = common.call(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
    if len(resp_str) > 3:
      jstr = json_loads(resp_str)
      mlog.info("Timezone Info = {0}".format(json.dumps(jstr,indent=4)))
      if _ofile is None: 
         mlog.error("No file provided .. exiting")
         sys.exit("No file provided .. exiting")
      _str = '/api/config/system/time-zone'
      out = common.create_out_data("PUT","200",_str,jstr)
      fp=open(_ofile,"w+")
      out1 = json.dumps(out, indent=4)
      fp.write(out1)
      fp.close()
    else:
      mlog.error("No data in timezone -- not writing output file outfile={0}".format(_ofile))
      return
    return ''

def get_dir_ntp_server ( _method, _uri, _payload,resp='200', _name=None,_ofile=None):
    global vnms, analy, cntlr, cust, mlog
    mlog.info("In function {0} with outfile={1}".format(get_dir_ntp_server.__name__,_ofile))
    resp2 = '202'
    vdict = {}
    vdict = {'body': _payload, 'resp': resp, 'resp2': resp2, 'method': _method, 'uri': _uri}
    [out, resp_str] = common.call(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
    if len(resp_str) > 3:
      jstr = json_loads(resp_str)
      mlog.info("NTP Info = {0}".format(json.dumps(jstr,indent=4)))
      if _ofile is None: 
         mlog.error("No file provided .. exiting")
         sys.exit("No file provided .. exiting")
      _str = '/api/config/system/ntp'
      newjstr = {"ntp" : jstr}
      out = common.create_out_data("PATCH","200",_str,newjstr)
      fp=open(_ofile,"w+")
      out1 = json.dumps(out, indent=4)
      fp.write(out1)
      fp.close()
    else:
      mlog.error("No data in ntp -- not writing output file outfile={0}".format(_ofile))
      return
    return ''

def get_dir_dns_server ( _method, _uri, _payload,resp='200', _name=None,_ofile=None):
    global vnms, analy, cntlr, cust, mlog
    mlog.info("In function {0} with outfile={1}".format(get_dir_dns_server.__name__,_ofile))
    resp2 = '202'
    vdict = {}
    vdict = {'body': _payload, 'resp': resp, 'resp2': resp2, 'method': _method, 'uri': _uri}
    [out, resp_str] = common.call(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
    if len(resp_str) > 3:
      jstr = json_loads(resp_str)
      mlog.info("DNS Info = {0}".format(json.dumps(jstr,indent=4)))

      if _ofile is None: 
         mlog.error("No file provided .. exiting")
         sys.exit("No file provided .. exiting")
      _str = '/api/config/system/dns'
      out = common.create_out_data("PUT","200",_str,jstr)
      fp=open(_ofile,"w+")
      out1 = json.dumps(out, indent=4)
      fp.write(out1)
      fp.close()
    else:
      mlog.error("No data in dns -- not writing output file outfile={0}".format(_ofile))
      return
    return ''

def get_org_data ( _method, _uri, _payload,resp='200', vd_data=None,vd_data1=None):
  global vnms, analy, cntlr, cust, admin, mlog
  mlog.info("In function " + get_org_data.__name__)
  resp2 = '202'
  vdict = {}
  vdict = {'body': _payload, 'resp': resp, 'resp2': resp2, 'method':_method , 'uri': _uri,
            'vd_ip' :  vd_data['vd_ip'], 'vd_rest_port': vd_data['vd_rest_port'],
            'auth': vd_data['auth'] }
  #[out, resp_str] = call(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
  [out, resp_str] = common.newcall(vdict,content_type='json',ncs_cmd="no",jsonflag=1)

  org_data = {}
  if len(resp_str) > 3:
    jstr = json_loads(resp_str)
    if "organizations" in jstr:
      for _elem in jstr["organizations"]:
        a={}
        a['name'] = _elem["name"]
        a["globalOrgId"] = _elem["globalOrgId"]
        a["providerOrg"] = _elem["providerOrg"]
        org_data[_elem["name"] ] = {}
        org_data[_elem["name"] ] = a
        if _elem["providerOrg"]: # This is the provider Org
          if _elem["name"] == glbl.vnms.data['parentOrgName']:
            mlog.info("Matched Provider Org = {0} with input file".format(_elem["name"]))
          else:  
            mlog.error("Did not match Provider Org = {0} and Input file = {1} ".format(_elem["name"],glbl.vnms.data['parentOrgName']))
        else: # This is a Child Org. Must Match with customer
          if _elem["name"] == glbl.cust.data['custName']:
            mlog.info("Matched Cistomer Org = {0} with input file".format(_elem["name"]))
          else: 
            mlog.error("Did not match Customer Org = {0} and Input file = {1} ".format(_elem["name"],glbl.cust.data['custName']))
            sys.exit.error("Did not match Customer Org = {0} and Input file = {1} ".format(_elem["name"],glbl.cust.data['custName']))



  vdict = {'body': _payload, 'resp': resp, 'resp2': resp2, 'method':_method , 'uri': _uri,
            'vd_ip' :  vd_data1['vd_ip'], 'vd_rest_port': vd_data1['vd_rest_port'],
            'auth': vd_data1['auth'] }
  #[out, resp_str] = call(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
  [out, resp_str] = common.newcall(vdict,content_type='json',ncs_cmd="no",jsonflag=1)

  if len(resp_str) > 3:
    jstr = json_loads(resp_str)
    if "organizations" in jstr:
      for _elem in jstr["organizations"]:
        if ( _elem["name"] in org_data and _elem["globalOrgId"] == org_data[_elem["name"]]["globalOrgId"] 
             and _elem["providerOrg"] == org_data[_elem["name"]]["providerOrg"]):
          mlog.info("Matched globalOrgId = {0} for ProviderOrg Data for Old and New CC for Org={1}".format(_elem["globalOrgId"], _elem["name"]))
        else:
          mlog.error ("Could not matched globalOrgId = {0} for ProviderOrg Data for Old and New CC Org={1}".format(_elem["globalOrgId"], _elem["name"]))

    

def get_nms_provider( _method, _uri, _payload,resp='200', _name=None,_ofile=None):
    global vnms, analy, cntlr, cust, mlog
    mlog.info("In function {0} with outfile={1}".format(get_nms_provider.__name__,_ofile))
    resp2 = '202'
    vdict = {}
    vdict = {'body': _payload, 'resp': resp, 'resp2': resp2, 'method': _method, 'uri': _uri}
    [out, resp_str] = common.call(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
    outjson = {}
    if len(resp_str) > 3:
       jstr = json_loads(resp_str)
       if "provider" in jstr:
           outjson["provider"] = {}
           if "datastore" in jstr["provider"]:  
               outjson["provider"]["datastore"] = jstr["provider"]["datastore"]  
           else:
               mlog.info("In function {0} but datastore not present".format(get_nms_provider.__name__))
           if "default-auth-connector" in jstr["provider"]:  
               outjson["provider"]["default-auth-connector"] = jstr["provider"]["default-auth-connector"]  
           else:
               mlog.info("In function {0} but default-auth-connector not present".format(get_nms_provider.__name__))
           if "auth-connectors" in jstr["provider"]:  
               outjson["provider"]["auth-connectors"] = jstr["provider"]["auth-connectors"]  
           else:
               mlog.info("In function {0} but auth-connector not present".format(get_nms_provider.__name__))
           if "plans" in jstr["provider"]:  
               outjson["provider"]["plans"] = jstr["provider"]["plans"]  
           else:
               mlog.info("In function {0} but plans not present".format(get_nms_provider.__name__))
           if "analytics-cluster" in jstr["provider"]:  
               outjson["provider"]["analytics-cluster"] = jstr["provider"]["analytics-cluster"]  
           else:
               mlog.info("In function {0} but analytics-cluster not present".format(get_nms_provider.__name__))
       if _ofile is None: 
           mlog.error("No file provided .. exiting")
           sys.exit("No file provided .. exiting")
       _str = '/api/config/nms/provider'
       out = common.create_out_data("PATCH","200",_str,outjson)
       mlog.info("Saving following NMS provider Info = {0}".format(json.dumps(outjson,indent=4)))
       fp=open(_ofile,"w+")
       out1 = json.dumps(out, indent=4)
       fp.write(out1)
       fp.close()
    else:
      mlog.info("Did not find proper data in function {0}".format(get_nms_provider.__name__))
      sys.exit("Did not find proper data in function {0}".format(get_nms_provider.__name__))
    get_wan_ntwk(_ofile)
    return ''

def create_delete_default_auth_connector(_ofile):
    out = common.create_out_data("PATCH","200",_str,jstr)
    fp=open(_ofile,"w+")
    out1 = json.dumps(out, indent=4)
    fp.write(out1)
    fp.close()
    #create_delete_default_auth_connector(_ofile)
    return ''

def get_dir_analytics_cluster ( _method, _uri, _payload,resp='200', _name=None,_ofile=None):
    global vnms, analy, cntlr, cust, mlog
    mlog.info("In function {0} with outfile={1}".format(get_dir_analytics_cluster.__name__,_ofile))
    resp2 = '202'
    vdict = {}
    vdict = {'body': _payload, 'resp': resp, 'resp2': resp2, 'method': _method, 'uri': _uri}
    [out, resp_str] = common.call(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
    if len(resp_str) > 3:
      jstr = json_loads(resp_str)
      mlog.info("Analytic Cluster = {0}".format(json.dumps(jstr,indent=4)))
    if _ofile is None: 
       mlog.error("No file provided .. exiting")
       sys.exit("No file provided .. exiting")
    _str = '/api/config/nms/provider/analytics-cluster'
    out = common.create_out_data("PATCH","200",_str,jstr)
    fp=open(_ofile,"w+")
    out1 = json.dumps(out, indent=4)
    fp.write(out1)
    fp.close()
    create_delete_default_auth_connector(_ofile)
    return ''

def get_dir_auth_connector ( _method, _uri, _payload,resp='200', _name=None,_ofile=None):
    global vnms, analy, cntlr, cust, mlog
    mlog.info("In function {0} with outfile={1}".format(get_dir_auth_connector.__name__,_ofile))
    resp2 = '202'
    vdict = {}
    vdict = {'body': _payload, 'resp': resp, 'resp2': resp2, 'method': _method, 'uri': _uri}
    [out, resp_str] = common.call(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
    jstr = json_loads(resp_str)
    newjstr = { "auth-connectors" : jstr }
    #pprint(jstr)
    if _ofile is None: 
       mlog.error("No file provided .. exiting")
       sys.exit("No file provided .. exiting")
    _str = '/api/config/nms/provider/auth-connectors'
    out = common.create_out_data("PATCH","200",_str,newjstr)
    fp=open(_ofile,"w+")
    out1 = json.dumps(out, indent=4)
    fp.write(out1)
    fp.close()
    return ''

def get_dir_default_auth_connector ( _method, _uri, _payload,resp='200', _name=None,_ofile=None):
    global vnms, analy, cntlr, cust, mlog
    mlog.info("In function {0} with outfile={1}".format(get_dir_default_auth_connector.__name__,_ofile))
    resp2 = '202'
    vdict = {}
    vdict = {'body': _payload, 'resp': resp, 'resp2': resp2, 'method': _method, 'uri': _uri}
    [out, resp_str] = common.call(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
    jstr = json_loads(resp_str)
    newjstr = { "provider" : jstr }
    #pprint(jstr)
    if _ofile is None: 
       mlog.error("No file provided .. exiting")
       sys.exit("No file provided .. exiting")
    _str = '/api/config/nms/provider'
    out = common.create_out_data("PATCH","200",_str,newjstr)
    fp=open(_ofile,"w+")
    out1 = json.dumps(out, indent=4)
    fp.write(out1)
    fp.close()
    return ''

def get_dir_auth_connector_config ( _method, _uri, _payload,resp='200', _name=None,_ofile=None):
    global vnms, analy, cntlr, cust, mlog
    mlog.info("In function {0} with outfile={1}".format(get_dir_auth_connector_config.__name__,_ofile))
    resp2 = '202'
    vdict = {}
    vdict = {'body': _payload, 'resp': resp, 'resp2': resp2, 'method': _method, 'uri': _uri}
    [out, resp_str] = common.call(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
    jstr = json_loads(resp_str)
    newjstr = { "auth-connectors" : jstr }
    #pprint(jstr)
    if _ofile is None: 
       mlog.error("No file provided .. exiting")
       sys.exit("No file provided .. exiting")
    _str = '/api/config/nms/provider/auth-connectors'
    out = common.create_out_data("PATCH","200",_str,newjstr)
    fp=open(_ofile,"w+")
    out1 = json.dumps(out, indent=4)
    fp.write(out1)
    fp.close()
    return ''

def get_controller_config( _method, _uri, _payload,resp='200', _name=None,_ofile=None):
    global vnms, analy, cntlr, cust, mlog


    vdict = {'body': _payload, 'resp': resp, 'resp2': resp2, 'method':_method , 'uri': _uri,
            'vd_ip' :  vd_data1['vd_ip'], 'vd_rest_port': vd_data1['vd_rest_port'],
            'auth': vd_data1['auth'] }
    #[out, resp_str] = call(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
    [out, resp_str] = common.newcall(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
    if len(resp_str) > 3:
      jstr = json_loads(resp_str)
      scrub_list = [ "clear", "crypto", "diagnostics", "debug", "operations" ]
      for i in scrub_list:
        common.scrub(jstr,i)
      cntlr_data = jstr


def get_controller_org( _method, _uri, _payload,resp='200', _name=None,_ofile=None):
    global vnms, analy, cntlr, cust, mlog
    mlog.info("In function {0} with outfile={1}".format(get_controller_org.__name__,_ofile))
    resp2 = '202'
    vdict = {}
    vdict = {'body': _payload, 'resp': resp, 'resp2': resp2, 'method': _method, 'uri': _uri}
    [out, resp_str] = common.call(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
    if len(resp_str) > 3:
      jstr = json_loads(resp_str)
      scrub_list = [ "operations", "uuid"]
      for i in scrub_list:
        common.scrub(jstr,i)
      newjstr = {}
      if "org" in jstr:
         for i in range(len(jstr["org"])):
             if i == 0 : newjstr["org"] = [None]*len(jstr["org"])
             newjstr["org"][i] = {}
             for _key,_val in jstr["org"][i].items():
                if _key == "sd-wan":
                   newjstr["org"][i]["sdwan:sd-wan"] = _val
                   mlog.info("sdwan info changed in org data in function {0}".format(get_controller_org.__name__))
                elif _key == "available-service-node-groups":
                   newjstr["org"][i]["available-service-node-groups:available-service-node-groups"] = _val
                   mlog.info("service node groups info changed in org data in function {0}".format(get_controller_org.__name__))
                else: 
                   newjstr["org"][i][_key] = _val
      else:
         mlog.error("Bad data received in org .. exiting")
         sys.exit("Bad data received in org .. exiting")
      if _ofile is None: 
         mlog.error("No file provided .. exiting")
         sys.exit("No file provided .. exiting")
      _str = '/api/config/devices/device/' + _name + '/config/orgs/org'
      out = common.create_out_data("PATCH","200",_str,newjstr)
      fp=open(_ofile,"w+")
      out1 = json.dumps(out, indent=4)
      fp.write(out1)
      fp.close()
    else:
      mlog.info("Did not find proper org data in function {0}".format(get_controller_org.__name__))
      sys.exit("Did not find proper org data in function {0}".format(get_controller_org.__name__))
    return ''

def get_controller_org_services( _method, _uri, _payload,resp='200', _name=None,vd_data=None,vd_data1=None,_ofile=None,option=0):
    global vnms, analy, cntlr, cust, mlog
    mlog.info("In function {0} with outfile={1}".format(get_controller_org_services.__name__,_ofile))
    resp2 = '202'
    vdict = {}
    vdict = {'body': _payload, 'resp': resp, 'resp2': resp2, 'method':_method , 'uri': _uri,
              'vd_ip' :  vd_data['vd_ip'], 'vd_rest_port': vd_data['vd_rest_port'],
              'auth': vd_data['auth'] }
    [out, resp_str] = common.newcall(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
    if len(resp_str) > 3:
      jstr = json_loads(resp_str)
      scrub_list = [ "device-id", "dynamic-address", "persistent-action" "pac", "vms", "user-identification", "objects", 
                      "keytab", "live-users", "operations" ]
      for i in scrub_list:
        common.scrub(jstr,i)

      newjstr = {}
      if "org-services" in jstr:
         for i in range(len(jstr["org-services"])):
            if i == 0 : newjstr["org-services"] = [None]*len(jstr["org-services"])
            newjstr["org-services"][i] = {}
            for _key,_val in jstr["org-services"][i].items():
              if _key == "adc":
                 newjstr["org-services"][i]["adc:adc"] = _val
                 mlog.info("adc info changed in org-services data in function {0}".format(get_controller_org_services.__name__))
              elif _key == "application-identification":
                 newjstr["org-services"][i]["appid:application-identification"] = _val
                 mlog.info("appid info changed in org-services data in function {0}".format(get_controller_org_services.__name__))
              elif _key == "crypto":
                 newjstr["org-services"][i]["crypto:crypto"] = _val
                 mlog.info("crypto info changed in org-services data in function {0}".format(get_controller_org_services.__name__))
              elif _key == "ipsec":
                 newjstr["org-services"][i]["ipsec:ipsec"] = _val
                 mlog.info("ipsec info changed in org-services data in function {0}".format(get_controller_org_services.__name__))
              elif _key == "pbf":
                 newjstr["org-services"][i]["pbf:pbf"] = _val
                 mlog.info("lef info changed in org-services data in function {0}".format(get_controller_org_services.__name__))
              elif _key == "lef":
                 newjstr["org-services"][i]["lef:lef"] = _val
                 mlog.info("lef info changed in org-services data in function {0}".format(get_controller_org_services.__name__))
              elif _key == "security":
                 newjstr["org-services"][i]["security:security"] = _val
                 mlog.info("security info changed in org-services data in function {0}".format(get_controller_org_services.__name__))
              elif _key == "traffic-monitoring":
                 newjstr["org-services"][i]["traffic-monitoring:traffic-monitoring"] = _val
                 mlog.info("security info changed in org-services data in function {0}".format(get_controller_org_services.__name__))
              elif _key == "url-filtering":
                 newjstr["org-services"][i]["url-filtering:url-filtering"] = _val
                 mlog.info("security info changed in org-services data in function {0}".format(get_controller_org_services.__name__))
              else: 
                 newjstr["org-services"][i][_key] = _val
      if _ofile is None: 
        mlog.error("No file provided .. exiting")
        sys.exit("No file provided .. exiting")

      _str = '/api/config/devices/device/' + _name + '/config/orgs/org-services'
      out = common.create_out_data("PATCH","200",_str,newjstr)
      fp=open(_ofile,"w+")
      out1 = json.dumps(out, indent=4)
      fp.write(out1)
      fp.close()
    else:
      mlog.info("Did not find proper org-services data in function {0}".format(get_controller_org_services.__name__))
      sys.exit("Did not find proper org-services data in function {0}".format(get_controller_org_services.__name__))

    # we now need to check the ipsec profile
    customer = glbl.cust.data["custName"]
    uri = _uri.rsplit("?")[0] +  "/" + customer + "/ipsec?deep=true"
    resp2 = '202'
    vdict = {}
    vdict = {'body': _payload, 'resp': resp, 'resp2': resp2, 'method':_method , 'uri': uri,
              'vd_ip' :  vd_data['vd_ip'], 'vd_rest_port': vd_data['vd_rest_port'],
              'auth': vd_data['auth'] }
    [out, resp_str] = common.newcall(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
    org_data = {}
    if len(resp_str) > 3:
      jstr = json_loads(resp_str)
      if "ipsec" in jstr:
        for _elem in jstr["ipsec"]["vpn-profile"]:
          if _elem["name"] == customer+"-PostStaging":
            org_data[_elem["name"]] = {}
            org_data[_elem["name"]]["ike"] = {}
            org_data[_elem["name"]]["ike"]["group"] = _elem["ike"]["group"]
            org_data[_elem["name"]]["ike"]["transform"] = _elem["ike"]["transform"]
            org_data[_elem["name"]]["ipsec"] = {}
            org_data[_elem["name"]]["ipsec"]["transform"] = _elem["ipsec"]["transform"]

    oldcntlr=glbl.cntlr.data["old_cntlr"][option]['controllerName']
    b=uri.split("/")
    for i in range(len(b)):
      if b[i] == "device": b[i+1] = oldcntlr
    uri1="/".join(b) 
    vdict = {'body': _payload, 'resp': resp, 'resp2': resp2, 'method':_method , 'uri': uri1,
              'vd_ip' :  vd_data1['vd_ip'], 'vd_rest_port': vd_data1['vd_rest_port'],
              'auth': vd_data1['auth'] }
    [out, resp_str] = common.newcall(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
    if len(resp_str) > 3:
      jstr = json_loads(resp_str)
      found = 0
      if "ipsec" in jstr:
        for _elem in jstr["ipsec"]["vpn-profile"]:
          if _elem["name"] == customer+"-PostStaging" and _elem["name"] in org_data:
            found = 1
            if "ike" in _elem and _elem["ike"]["group"] == org_data[_elem["name"]]["ike"]["group"]:
              mlog.info("IKE Group on Old Director={0} matched New Director={1} for Controller={2}".format(_elem["ike"]["group"],org_data[_elem["name"]]["ike"]["group"],int(option+1)))
            else:
              mlog.info("IKE Group on Old Director={0} did not match New Director={1} for Controller={2}".format(_elem["ike"]["group"],org_data[_elem["name"]]["ike"]["group"],int(option+1)))
            if "ike" in _elem and _elem["ike"]["transform"] == org_data[_elem["name"]]["ike"]["transform"]:
              mlog.info("IKE transform on Old Director={0} matched New Director={1} for Controller={2}".format(_elem["ike"]["transform"],org_data[_elem["name"]]["ike"]["transform"],int(option+1)))
            else:
              mlog.error("IKE transform on Old Director={0} did not match New Director={1} for Controller={2}".format(_elem["ike"]["transform"],org_data[_elem["name"]]["ike"]["transform"],int(option+1)))
            if "ipsec" in _elem and _elem["ipsec"]["transform"] == org_data[_elem["name"]]["ipsec"]["transform"]:
              mlog.info("IPSEC transform on Old Director={0} matched New Director={1} for Controller={2}".format(_elem["ipsec"]["transform"],org_data[_elem["name"]]["ipsec"]["transform"],int(option+1)))
            else:
              mlog.error("IPSEC transform on Old Director={0} did not match New Director={1} for Controller={2}".format(_elem["ipsec"]["transform"],org_data[_elem["name"]]["ipsec"]["transform"],int(option+1)))

        if found == 0: # We did not find a single VPN Profile
          mlog.error("No matching VPN Profile on Old Director with VPN Profile on New Director={0} for Controller={1}".format(customer+"-PostStaging",int(option+1)))

    return ''

def get_controller_system ( _method, _uri, _payload,resp='200', _name=None,_ofile=None):
    global vnms, analy, cntlr, cust, mlog
    mlog.info("In function {0} with outfile={1}".format(get_controller_system.__name__,_ofile))
    resp2 = '202'
    vdict = {}
    vdict = {'body': _payload, 'resp': resp, 'resp2': resp2, 'method': _method, 'uri': _uri}
    [out, resp_str] = common.call(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
    if len(resp_str) > 3:
      jstr = json_loads(resp_str)
      scrub_list = [ "operations"]

      for i in scrub_list:
        common.scrub(jstr,i)
      if "system" in jstr and "users" in jstr["system"]:
         for i in range(len(jstr["system"]["users"])):
            if "password" in jstr["system"]["users"][i]:
              mlog.info("Changing the password of users ".format(i))
              jstr["system"]["users"][i]["password"] = "versa123"
           
      #newjstr["config"]["interfaces:interfaces"] = jstr
      if _ofile is None or _name is None :
        mlog.error("No file or name provided .. exiting")
        sys.exit("No file or name provided .. exiting")
      _str = '/api/config/devices/device/' + _name + '/config/system'
      out = common.create_out_data("PATCH","200",_str,jstr)
      fp=open(_ofile,"w+")
      out1 = json.dumps(out, indent=4)
      fp.write(out1)
      fp.close()
    else:
      mlog.info("Did not find proper system data in function {0}".format(get_controller_system.__name__))
      sys.exit("Did not find proper system data in function {0}".format(get_controller_system.__name__))
    return ''

def get_controller_vni( _method, _uri, _payload,resp='200', _name=None,_ofile=None):
    global vnms, analy, cntlr, cust, mlog
    resp2 = '202'
    vdict = {}
    mlog.info("In function {0} with outfile={1}".format(get_controller_vni.__name__,_ofile))
    vdict = {'body': _payload, 'resp': resp, 'resp2': resp2, 'method': _method, 'uri': _uri}
    [out, resp_str] = common.call(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
    if len(resp_str) > 3:
       jstr = json_loads(resp_str)
       newjstr = { "config" : { "interfaces:interfaces": jstr } }
       #newjstr["config"]["interfaces:interfaces"] = jstr
       if _ofile is None or _name is None :
          mlog.error("No file or name provided .. exiting")
          sys.exit("No file or name provided .. exiting")
       _str = '/api/config/devices/device/' + _name + '/config'
       out = common.create_out_data("PATCH","200",_str,newjstr)
       fp=open(_ofile,"w+")
       out1 = json.dumps(out, indent=4)
       fp.write(out1)
       fp.close()
    else:
       mlog.info("Did not find proper vni data in function {0}".format(get_controller_vni.__name__))
       sys.exit("Did not find proper vni data in function {0}".format(get_controller_vni.__name__))
    return ''


def get_controller_alarms( _method, _uri, _payload,resp='200', _name=None,_ofile=None):
    global vnms, analy, cntlr, cust, mlog
    resp2 = '202'
    vdict = {}
    mlog.info("In function {0} with outfile={1}".format(get_controller_alarms.__name__,_ofile))
    vdict = {'body': _payload, 'resp': resp, 'resp2': resp2, 'method': _method, 'uri': _uri}
    [out, resp_str] = common.call(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
    if len(resp_str) > 3:
      jstr = json_loads(resp_str)
      if "alarms" in jstr:
         newjstr = { "config" : { "oam:alarms": jstr["alarms"] } }
         if _ofile is None or _name is None :
            mlog.error("No file or name provided .. exiting")
            sys.exit("No file or name provided .. exiting")
         _str = '/api/config/devices/device/' + _name + '/config'
         out = common.create_out_data("PATCH","200",_str,newjstr)
         fp=open(_ofile,"w+")
         out1 = json.dumps(out, indent=4)
         fp.write(out1)
         fp.close()
      else:
         mlog.info("Did not find proper routing data in function {0}".format(get_controller_alarms.__name__))
         return
    else:
      mlog.info("Did not find proper routing data in function {0}".format(get_controller_alarms.__name__))
    return ''


def get_controller_synch( _method, _uri, _payload,resp='200', _name=None,_ofile=None):
    # this does not call any rest api. it just writes things to a file
    global vnms, analy, cntlr, cust, mlog
    mlog.info("In function {0} with outfile={1}".format(get_controller_synch.__name__,_ofile))
    resp2 = '202'
    vdict = {}
    vdict = {'body': _payload, 'resp': resp, 'resp2': resp2, 'method': _method, 'uri': _uri}
    jstr = json_loads(_payload)
    if _ofile is None or _name is None :
       mlog.error("No file provided .. exiting")
       sys.exit("No file provided .. exiting")
    _str = _uri
    out = common.create_out_data(_method,resp,_str,jstr)
    fp=open(_ofile,"w+")
    out1 = json.dumps(out, indent=4)
    fp.write(out1)
    fp.close()
    return ''

def get_controller_commit( _method, _uri, _payload,resp='200', _name=None,_ofile=None):
    # this does not call any rest api. it just writes things to a file
    global vnms, analy, cntlr, cust, mlog
    mlog.info("In function {0} with outfile={1}".format(get_controller_commit.__name__,_ofile))
    resp2 = '202'
    vdict = {}
    vdict = {'body': _payload, 'resp': resp, 'resp2': resp2, 'method': _method, 'uri': _uri}
    jstr = json_loads(_payload)
    if _ofile is None or _name is None :
       mlog.error("No file provided .. exiting")
       sys.exit("No file provided .. exiting")
    _str = _uri
    out = common.create_out_data(_method,resp,_str,jstr)
    fp=open(_ofile,"w+")
    out1 = json.dumps(out, indent=4)
    fp.write(out1)
    fp.close()
    return ''

def get_device_group( _method, _uri, _payload,resp='200', _name=None,_ofile=None):
    # this does not call any rest api. it just writes things to a file
    global vnms, analy, cntlr, cust, mlog
    mlog.info("In function {0} with outfile={1}".format(get_device_group.__name__,_ofile))
    resp2 = '202'
    vdict = {}
    vdict = {'body': _payload, 'resp': resp, 'resp2': resp2, 'method': _method, 'uri': _uri}
    jstr = json_loads(_payload)
    if _ofile is None or _name is None :
       mlog.error("No file provided .. exiting")
       sys.exit("No file provided .. exiting")
    _str = _uri
    out = common.create_out_data(_method,resp,_str,jstr)
    fp=open(_ofile,"w+")
    out1 = json.dumps(out, indent=4)
    fp.write(out1)
    fp.close()
    return ''

def controller_config_build( _method, _uri, _payload,resp='200', _name=None,_ofile=None):
    # this does not call any rest api. it just writes things to a file
    global vnms, analy, cntlr, cust, mlog
    mlog.info("In function {0} with outfile={1}".format(controller_config_build.__name__,_ofile))
    resp2 = '202'
    vdict = {}
    vdict = {'body': _payload, 'resp': resp, 'resp2': resp2, 'method': _method, 'uri': _uri}
    jstr = json_loads(_payload)
    if _ofile is None or _name is None :
       mlog.error("No file provided .. exiting")
       sys.exit("No file provided .. exiting")
    _str = _uri
    out = common.create_out_data(_method,resp,_str,jstr)
    fp=open(_ofile,"w+")
    out1 = json.dumps(out, indent=4)
    fp.write(out1)
    fp.close()
    return ''

def get_wan_ntwk( ofile):
    # this does not call any rest api. it just writes things to a file
    global vnms, analy, cntlr, cust, mlog
    mlog.info("In function {0} with outfile={1}".format(get_wan_ntwk.__name__,ofile))
    resp2 = '202'
    if ofile is None:
       mlog.error("No file provided .. exiting")
       sys.exit("No file provided .. exiting")

    mtch = re.search(r'(.+)(\d{3})_.+\.json$', ofile)
    if mtch :
      jstr = {}
      _str = '/nextgen/organization/' + glbl.vnms.data["parentOrgName"]
      out = common.create_out_data("GET","200",_str,jstr)
      fil = "in_phase2/"+ "{:03d}_GET_PARENT_ORGID.json".format(int(mtch.group(2)) + 1)
      fp=open(fil,"w+")
      out1 = json.dumps(out, indent=4)
      fp.write(out1)
      fp.close()

      _str = '/nextgen/organization/' + '{{parentOrgUUID}}' + '/wan-networks?offset=0&limit=25'
      out = common.create_out_data("GET","200",_str,jstr)
      fil = "in_phase2/" + "{:03d}_GET_WAN_NETWORK.json".format(int(mtch.group(2)) + 2)
      fp=open(fil,"w+")
      out1 = json.dumps(out, indent=4)
      fp.write(out1)
      fp.close()
    return ''

def deploy_controller_new( _method, _uri, _payload,resp='200', _name=None,_ofile=None):
    # this does not call any rest api. it just writes things to a file
    global vnms, analy, cntlr, cust, mlog
    mlog.info("In function {0} with outfile={1}".format(deploy_controller_new.__name__,_ofile))
    resp2 = '202'
    vdict = {}
    vdict = {'body': _payload, 'resp': resp, 'resp2': resp2, 'method': _method, 'uri': _uri}
    jstr = _payload
    if _ofile is None or _name is None :
       mlog.error("No file provided .. exiting")
       sys.exit("No file provided .. exiting")
    _str = '/vnms/sdwan/workflow/controllers/controller/deploy/' +  _name 
    out = common.create_out_data("POST","200",_str,jstr)
    fp=open(_ofile,"w+")
    out1 = json.dumps(out, indent=4)
    fp.write(out1)
    fp.close()
    return ''

def get_controller_ntp ( _method, _uri, _payload,resp='200', _name=None,_ofile=None):
    global vnms, analy, cntlr, cust, mlog
    resp2 = '202'
    vdict = {}
    mlog.info("In function {0} with outfile={1}".format(get_controller_ntp.__name__,_ofile))
    vdict = {'body': _payload, 'resp': resp, 'resp2': resp2, 'method': _method, 'uri': _uri}
    [out, resp_str] = common.call(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
    if len(resp_str) > 3: 
        jstr = json_loads(resp_str)
        newjstr = { "config" : { "ntp:ntp": jstr["ntp"] } }
        #newjstr["config"]["interfaces:interfaces"] = jstr
        if _ofile is None or _name is None :
           mlog.error("No file provided .. exiting")
           sys.exit("No file provided .. exiting")
        _str = '/api/config/devices/device/' + _name + '/config'
        out = common.create_out_data("PATCH","200",_str,newjstr)
        fp=open(_ofile,"w+")
        out1 = json.dumps(out, indent=4)
        fp.write(out1)
        fp.close()
    else:
        mlog.info("Did not find proper ntp data in function {0}".format(get_controller_ntp.__name__))
        return
    return ''

def get_controller_routing ( _method, _uri, _payload,resp='200', _name=None,_ofile=None):
    global vnms, analy, cntlr, cust, mlog
    resp2 = '202'
    vdict = {}
    mlog.info("In function {0} with outfile={1}".format(get_controller_routing.__name__,_ofile))
    vdict = {'body': _payload, 'resp': resp, 'resp2': resp2, 'method': _method, 'uri': _uri}
    [out, resp_str] = common.call(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
    if len(resp_str) > 3: 
        jstr = json_loads(resp_str)
        newjstr = { "config" : { "routing-module:routing-instances": jstr["routing-instances"] } }
        if _ofile is None or _name is None :
           mlog.error("No file provided .. exiting")
           sys.exit("No file provided .. exiting")
        newjstr = { "config" : { "routing-module:routing-instances": jstr["routing-instances"] } }
        _str = '/api/config/devices/device/' + _name + '/config'
        out = common.create_out_data("PATCH","200",_str,newjstr)
        fp=open(_ofile,"w+")
        out1 = json.dumps(out, indent=4)
        fp.write(out1)
        fp.close()
    else:
        mlog.error("Did not find proper routing data in function {0}".format(get_controller_routing.__name__))
        sys.exit("Did not find proper routing data in function {0}".format(get_controller_routing.__name__))
    return ''

def write_outfile(_vnms,_analy,_cntlr,_cust, _admin):
    global vnms, analy, cntlr, cust, admin, mlog
    mlog.info("In function {0} : Output file:vm_phase2.json".format(write_outfile.__name__))
    jstr = {}
    jstr["Vnms"] = _vnms.data
    jstr["Analytics"] = _analy.data
    jstr["Controller"] = _cntlr.data
    jstr["Admin"] = _admin.data
    jstr["Customer"] = _cust.data
    fin=open("vm_phase2.json", "w+")
    mstr1 = json.dumps(jstr, indent=4)
    fin.write(mstr1)
    fin.close()


def get_sdwan_workflow_list( _method, _uri, _payload,resp='200', _ofile=None):
    global vnms, analy, cntlr, cust, admin, mlog
    resp2 = '202'
    vdict = {}
    mlog.info("In function {0} ".format(get_sdwan_workflow_list.__name__))
    vdict = {'body': _payload, 'resp': resp, 'resp2': resp2, 'method': _method, 'uri': _uri}
    [out, resp_str] = common.call(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
    if len(resp_str) > 3: 
      jstr = json_loads(resp_str)
      if "versanms.sdwan-controller-list" in jstr:
        if len(jstr["versanms.sdwan-controller-list"]) == 0 or len(jstr["versanms.sdwan-controller-list"]) > 2 :
          mlog.error("Bad len = {0} in return .. exiting".format(len(jstr["versanms.sdwan-controller-list"])))
          sys.exit("did not get right number of controllers")
        else:
          cntlr_names = list(map(lambda x : x["controllerName"], jstr["versanms.sdwan-controller-list"]))
          c_names = determine_active_peer_cntlr(cntlr_names,  _method, _uri, _payload,resp='200')
          if None not in c_names:
            if c_names[0]  == jstr["versanms.sdwan-controller-list"][0]["controllerName"]: 
              glbl.cntlr.data['new_cntlr'].append(jstr["versanms.sdwan-controller-list"][0])
              glbl.cntlr.data['new_cntlr'].append(jstr["versanms.sdwan-controller-list"][1])
            else: 
              glbl.cntlr.data['new_cntlr'].append(jstr["versanms.sdwan-controller-list"][1])
              glbl.cntlr.data['new_cntlr'].append(jstr["versanms.sdwan-controller-list"][0])
          else:  # we use siteID 
            site1 = int(jstr["versanms.sdwan-controller-list"][0]["siteId"])
            site2 = int(jstr["versanms.sdwan-controller-list"][1]["siteId"])
            if site1 < site2:
              glbl.cntlr.data['new_cntlr'].append(jstr["versanms.sdwan-controller-list"][0])
              glbl.cntlr.data['new_cntlr'].append(jstr["versanms.sdwan-controller-list"][1])
            else:
              glbl.cntlr.data['new_cntlr'].append(jstr["versanms.sdwan-controller-list"][1])
              glbl.cntlr.data['new_cntlr'].append(jstr["versanms.sdwan-controller-list"][0])
            #glbl.cntlr.data[0] = jstr["versanms.sdwan-controller-list"][0]
            #glbl.cntlr.data[1] = jstr["versanms.sdwan-controller-list"][1]
            #if debug : pprint(glbl.cntlr.data)
          write_outfile(glbl.vnms,glbl.analy,glbl.cntlr,glbl.cust, glbl.admin)
    else:
      mlog.error("Did not find proper sdwan workflow data in function {0}".format(get_sdwan_workflow_list.__name__))
      sys.exit("Did not get proper sdwan worflow data ")
    return ''
    
def determine_active_peer_cntlr(_cnames, _method, _uri, _payload,resp='200'):
    global vnms, analy, cntlr, cust, mlog
    resp2 = '202'

    _oname = [None] * 2
    found = 0
    for elem in _cnames:
      uri = _uri.rsplit("?")[0] +  "/controller/" + elem
      vdict = {}
      vdict = {'body': _payload, 'resp': resp, 'resp2': resp2, 'method': _method, 'uri': uri}
      mlog.info("In function {0} ".format(determine_active_peer_cntlr.__name__))
      [out, resp_str] = common.call(vdict,content_type='json',ncs_cmd="no")
      if len(resp_str) > 3: 
        jstr = json_loads(resp_str)
        if "versanms.sdwan-controller-workflow" in jstr:
          if "peerControllers" in jstr["versanms.sdwan-controller-workflow"]:
            _oname[1] = jstr["controllerName"] # this is the secondary controller
            found =  found + 1
          else:
            _oname[0] = jstr["controllerName"] # this is the secondary controller
            found =  found + 1
      else:
          mlog.error("Did not find proper data in function {0}".format(determine_active_peer_cntlr.__name__))
    if found == 2: 
      return _oname
    else: return [ None, None ]

      return ''
    
def get_controller_workflow( _method, _uri, _payload,resp='200', _ofile=None):
    global vnms, analy, cntlr, cust, mlog
    resp2 = '202'
    vdict = {}
    vdict = {'body': _payload, 'resp': resp, 'resp2': resp2, 'method': _method, 'uri': _uri}
    mlog.info("In function {0} with outfile={1}".format(get_controller_workflow.__name__,_ofile))
    [out, resp_str] = common.call(vdict,content_type='json',ncs_cmd="no")
    if len(resp_str) > 3: 
        jstr = json_loads(resp_str)
        if _ofile is None: 
           mlog.error("No file provided .. exiting")
           sys.exit("No file provided .. exiting")
        out = common.create_out_data("POST","200","/vnms/sdwan/workflow/controllers/controller", jstr)
        fp=open(_ofile,"w+")
        out1 = json.dumps(out, indent=4)
        fp.write(out1)
        fp.close()
    else:
        mlog.error("Did not find proper ntp data in function {0}".format(get_controller_routing.__name__))
        sys.exit("Did not find proper ntp data in function {0}".format(get_controller_routing.__name__))
    return ''

def deploy_org_workflow( _method, _uri, _payload,resp='200', _name=None,vd_data=None,vd_data1=None,_ofile=None):
    global vnms, analy, cntlr, cust, mlog
    resp2 = '202'
    vdict = {}
    vdict = {'body': _payload, 'resp': resp, 'resp2': resp2, 'method':_method , 'uri': _uri,
              'vd_ip' :  vd_data['vd_ip'], 'vd_rest_port': vd_data['vd_rest_port'],
              'auth': vd_data['auth'] }
    mlog.info("In function {0} with outfile={1}".format(deploy_org_workflow.__name__,_ofile))
    [out, resp_str] = common.newcall(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
    if len(resp_str) > 3: 
      jstr = json_loads(resp_str)
      if _ofile is None or _name is None: 
         mlog.error("No file provided .. exiting")
         sys.exit("No file provided .. exiting")
      _str='/vnms/sdwan/workflow/orgs/org/' + _name
      out = common.create_out_data("PUT","200",_str, jstr)
      fp=open(_ofile,"w+")
      out1 = json.dumps(out, indent=4)
      fp.write(out1)
      fp.close()
      org_data = {}
      cnt=0
      if "versanms.sdwan-org-workflow" in jstr:
        y = jstr["versanms.sdwan-org-workflow"]["orgName"]
        org_data[y] = {}
        for _elem in jstr["versanms.sdwan-org-workflow"]["vrfs"]:
          org_data[y][_elem["name"] ] = _elem["id"]
          cnt=cnt+1

      resp2 = '202'
      vdict = {}
      vdict = {'body': _payload, 'resp': resp, 'resp2': resp2, 'method':_method , 'uri': _uri,
                'vd_ip' :  vd_data1['vd_ip'], 'vd_rest_port': vd_data1['vd_rest_port'],
                'auth': vd_data1['auth'] }
      [out, resp_str] = common.newcall(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
      if len(resp_str) > 3:
        jstr = json_loads(resp_str)
        cnt1=0
        if "versanms.sdwan-org-workflow" in jstr:
          y = jstr["versanms.sdwan-org-workflow"]["orgName"]
          if y in org_data:
            for _elem in jstr["versanms.sdwan-org-workflow"]["vrfs"]:
              cnt1 = cnt1 +1
              if ( _elem["name"] in org_data[y] and _elem["id"] == org_data[y][_elem["name"]]):
                mlog.info("VRF ID={0} with Name={1} Matched for Old Director and New Director".format(_elem["id"],_elem["name"]))
              else:
                mlog.error("VRF ID={0} with Name={1} Matched for Old Director and New Director".format(_elem["id"],_elem["name"]))
            if cnt != cnt1:
                mlog.error("No of VRF ID={0} on New Director and {1} on Old Director".format(cnt,cnt1))
    else:
        mlog.error("Did not find proper response data in function {0}".format(deploy_org_workflow.__name__))
        sys.exit("Did not find proper response data in function {0}".format(deploy_org_workflow.__name__))
    return ''
   
#def analytics_call( _method, _uri,_payload,resp='200'):
#    global debug, admin
#    vdict = {}
#    vdict = {'body': _payload, 'resp': resp, 'method': _method, 'uri': _uri, 'ip': glbl.admin.data['analy_ip']}
#    out = analycall(vdict)
#    return ''

# the only difference between analytics_call and analytics_call1 is the ip which we are passing in the vdict
#def analytics1_call( _method, _uri,_payload,resp='200'):
#    global debug, admin
#    vdict = {}
#    vdict = {'body': _payload, 'resp': resp, 'method': _method, 'uri': _uri, 'ip': glbl.admin.data['analy_ip1']}
#    out = analycall(vdict)
#    return ''

def create_dns_config( _method, _uri,_payload,resp='200'):
    vdict = {}
    vdict = {'body': _payload, 'resp': resp, 'method': _method, 'uri': _uri}
    [out, resp_str] = common.call(vdict,content_type='json',ncs_cmd="no")
    print(json_loads(resp_str))
    return ''

def yes_or_no(question):
    if pyVer.major == 3:
      reply = str(input(question+' (y/n): ')).lower().strip()
    else: 
      reply = str(raw_input(question+' (y/n): ')).lower().strip()
    if reply[0] == 'y':
        return True
    if reply[0] == 'n':
        return False
    else:
        return yes_or_no("Ughhh... please re-enter ") 

def setup_files():
    
    #"005_GET_ANALYTICS_CLUSTER.json" : _str + '005_CREATE_ANALYTICS_CLUSTER.json',
    #"006_GET_DEFAULT_AUTH_CONNECTOR.json" : _str + '007_CREATE_DEFAULT_AUTH_CONNECTOR.json',
    #"007_GET_AUTH_CONNECTOR.json" : _str + '006_CREATE_AUTH_CONNECTOR.json',
    #"008_GET_AUTH_CONNECTOR_CONFIG.json" : _str + '008_CREATE_AUTH_CONNECTOR_CONFIG.json',

    _str = "in_phase2/"
    vdict = {
    "001_GET_RELEASE_INFO.json" : _str + '001_GET_RELEASE_INFO.json',
    "002_GET_TIME_ZONE.json" :  _str + '002_CREATE_TIME_ZONE.json',
    "003_GET_NTP_SERVER.json" : _str + '003_CREATE_NTP_SERVER.json' , 
    "004_GET_DNS_SERVER.json" : _str + '004_CREATE_DNS_SERVER.json' , 
    "005_GET_NMS_PROVIDER.json" : _str + "005_SET_NMS_PROVIDER.json",
    "006_GET_ORG_LIST.json" : "",
    "009_GET_SDWAN_WORKFLOW_LIST.json" : "",
    "010_GET_OLD_SDWAN_WORKFLOW_LIST.json" : "",
    "011_GET_OLD_CONTROLLER_WORKFLOW.json" : "",
    "012_GET_OLD_PEER_CONTROLLER_WORKFLOW.json" : "",
    "030_GET_CONTROLLER_WORKFLOW.json":  _str + '030_CREATE_CONTROLLER.json',
    "031_GET_PEER_CONTROLLER_WORKFLOW.json": _str + '035_CREATE_PEER_CONTROLLER.json',
    "032_GET_DEPLOY_CONTROLLER_WORKFLOW.json": _str + '031_DEPLOY_CONTROLLER_WORKFLOW.json',
    "033_GET_DEPLOY_PEER_CONTROLLER_WORKFLOW.json": _str + '036_DEPLOY_PEER_CONTROLLER_WORKFLOW.json',
    "038_GET_ORG_WORKFLOW.json": _str + '038_ORG_DEPLOY_WORKFLOW.json',
    "050_GET_CONTROLLER_CONFIG_BUILD.json": _str + '050_SET_CONTROLLER_CONFIG_BUILD.json',
    "051_GET_CONTROLLER_VNI.json": _str + '051_SET_CONTROLLER_VNI.json',
    "052_GET_CONTROLLER_ROUTING.json": _str + '052_SET_CONTROLLER_ROUTING.json',
    "053_GET_CONTROLLER_NTP.json": _str + '053_SET_CONTROLLER_NTP.json',
    "054_GET_CONTROLLER_OAM_ALARMS.json": _str + '054_SET_CONTROLLER_OAM_ALARMS.json',
    "055_GET_CONTROLLER_ORG_SERVICES.json":  _str + '055_SET_CONTROLLER_ORG_SERVICES.json',
    "056_GET_CONTROLLER_ORG.json": _str + '056_SET_CONTROLLER_ORG.json',
    "057_GET_CONTROLLER_SYSTEM.json": _str + '057_SET_CONTROLLER_SYSTEM.json',
    "058_GET_CONTROLLER_COMMIT.json": _str + '058_SET_CONTROLLER_COMMIT.json',
    "059_GET_CONTROLLER_SYNCH.json" : _str + '059_SET_CONTROLLER_SYNCH.json',
    "060_GET_PEER_CONTROLLER_CONFIG_BUILD.json": _str + '060_SET_PEER_CONTROLLER_CONFIG_BUILD.json',
    "061_GET_PEER_CONTROLLER_VNI.json": _str + '061_SET_PEER_CONTROLLER_VNI.json',
    "062_GET_PEER_CONTROLLER_ROUTING.json": _str + '062_SET_PEER_CONTROLLER_ROUTING.json',
    "063_GET_PEER_CONTROLLER_NTP.json": _str + '063_SET_PEER_CONTROLLER_NTP.json',
    "064_GET_PEER_CONTROLLER_OAM_ALARMS.json": _str + '064_SET_PEER_CONTROLLER_OAM_ALARMS.json',
    "065_GET_PEER_CONTROLLER_ORG_SERVICES.json": _str + '065_SET_PEER_CONTROLLER_ORG_SERVICES.json',
    "066_GET_PEER_CONTROLLER_ORG.json": _str + '066_SET_PEER_CONTROLLER_ORG.json',
    "067_GET_PEER_CONTROLLER_SYSTEM.json":  _str + '067_SET_PEER_CONTROLLER_SYSTEM.json',
    "068_GET_PEER_CONTROLLER_COMMIT.json" : _str + '068_SET_PEER_CONTROLLER_COMMIT.json',
    "069_GET_PEER_CONTROLLER_SYNCH.json" :  _str + '069_SET_PEER_CONTROLLER_SYNCH.json',
    "090_GET_DEVICE_GROUP.json" :  _str + '090_GET_DEVICE_GROUP.json',
    "091_GET_RECOVERY_BACKUP.json" :  _str + "junk"
    }
    return vdict

def transform_in(infile):
    global vnms, analy, cntlr, cust, admin, mlog, mdict

    if infile in mdict:
      return mdict[infile]
    else:
      mlog.error("Bad file={0} provided .. exiting".format(infile))
      sys.exit("Bad file={0} provided .. exiting".format(infile))

      

def main():
    #global vnms, analy, cntlr, cust, admin, auth, debug, mlog, mdict
    #mdict = readfile("in_rest.cfg")
    global mlog, mdict
    argcheck()
    debug = int(args['debug'])
    infile = args['file']
    LOG_FILENAME = 'vmMigrate.log'
    LOG_SIZE = 8 * 1024 * 1024
    mlog,f_hndlr,s_hndlr=glbl.init(infile,LOG_FILENAME, LOG_SIZE,"VMMigr1",debug)
    if debug == 0:
      glbl.setup_level(f_hndlr, logging.INFO) # Setting fileHandler loglevel
      glbl.setup_level(s_hndlr, logging.WARNING) # Setting stream Handler loglevel
    else:
      glbl.setup_level(f_hndlr, logging.INFO)
      glbl.setup_level(s_hndlr, logging.INFO)
    mlog.warn(bcolors.OKWARN + "===============Starting Phase 1 Execution==========" + bcolors.ENDC)

    write_outfile(glbl.vnms,glbl.analy,glbl.cntlr,glbl.cust, glbl.admin)

    if len(glbl.cntlr.data["old_cntlr"]) != 2:
      mlog.error("Invalid: input file does not have Old Controller data")
      sys.exit("Invalid: input file does not have Old Controller data")


    mdict = setup_files()

    fil = OrderedDict()
    #############################NEW###########################

    fil['GET_RELEASE_INFO.json'] = get_dir_release_info
    fil['GET_TIME_ZONE.json'] = get_dir_time_zones
    fil['GET_NTP_SERVER.json'] = get_dir_ntp_server
    fil['GET_DNS_SERVER.json'] = get_dir_dns_server
    fil['GET_NMS_PROVIDER.json'] = get_nms_provider
    fil['GET_ORG_LIST.json'] = get_org_data

    #fil['GET_ANALYTICS_CLUSTER.json'] = get_dir_analytics_cluster
    #fil['GET_DEFAULT_AUTH_CONNECTOR.json'] = get_dir_default_auth_connector
    #fil['GET_AUTH_CONNECTOR.json'] = get_dir_auth_connector
    #fil['GET_AUTH_CONNECTOR_CONFIG.json'] = get_dir_auth_connector_config

    fil['GET_SDWAN_WORKFLOW_LIST.json'] = get_sdwan_workflow_list
    fil['GET_OLD_SDWAN_WORKFLOW_LIST.json'] = get_old_sdwan_workflow_list
    fil['GET_CONTROLLER_WORKFLOW.json'] = get_controller_workflow
    fil['GET_PEER_CONTROLLER_WORKFLOW.json'] = get_controller_workflow

    fil['GET_DEPLOY_CONTROLLER_WORKFLOW.json'] = deploy_controller_new
    fil['GET_DEPLOY_PEER_CONTROLLER_WORKFLOW.json'] = deploy_controller_new
    fil['GET_ORG_WORKFLOW.json'] = deploy_org_workflow
    fil['GET_CONTROLLER_CONFIG_BUILD.json'] = controller_config_build
    fil['GET_PEER_CONTROLLER_CONFIG_BUILD.json'] = controller_config_build

    fil['GET_CONTROLLER_VNI.json'] = get_controller_vni 
    fil['GET_PEER_CONTROLLER_VNI.json'] = get_controller_vni 

    fil['GET_CONTROLLER_ROUTING.json'] = get_controller_routing
    fil['GET_PEER_CONTROLLER_ROUTING.json'] = get_controller_routing

    fil['GET_CONTROLLER_NTP.json'] = get_controller_ntp 
    fil['GET_PEER_CONTROLLER_NTP.json'] = get_controller_ntp 

    fil['GET_CONTROLLER_OAM_ALARMS.json'] = get_controller_alarms
    fil['GET_PEER_CONTROLLER_OAM_ALARMS.json'] = get_controller_alarms

    fil['GET_CONTROLLER_ORG_SERVICES.json'] = get_controller_org_services
    fil['GET_PEER_CONTROLLER_ORG_SERVICES.json'] = get_controller_org_services

    fil['GET_CONTROLLER_ORG.json'] = get_controller_org
    fil['GET_PEER_CONTROLLER_ORG.json'] = get_controller_org

    fil['GET_CONTROLLER_SYSTEM.json'] = get_controller_system
    fil['GET_PEER_CONTROLLER_SYSTEM.json'] = get_controller_system

    fil['GET_CONTROLLER_COMMIT.json'] = get_controller_commit
    fil['GET_PEER_CONTROLLER_COMMIT.json'] = get_controller_commit

    fil['GET_CONTROLLER_SYNCH.json'] = get_controller_synch
    fil['GET_PEER_CONTROLLER_SYNCH.json'] = get_controller_synch
    fil['GET_DEVICE_GROUP.json'] = get_device_group
    fil['GET_RECOVERY_BACKUP.json'] = get_backup


    template_path = os.path.abspath(sys.argv[0]).rsplit("/",1)[0] + "/" + "in_phase1"
    if not os.path.exists( template_path ):
      sys.exit("Directory: {0} does not exists".format(template_path)) 
    tmp_outpath = os.path.abspath(sys.argv[0]).rsplit("/",1)[0] + "/" + "in_phase2"
    if not os.path.exists( tmp_outpath ):
      os.makedirs(tmp_outpath )

    newdir= {'vd_ip' :  glbl.admin.data['new_dir']['vd_ip'],
            'vd_rest_port': glbl.admin.data['new_dir']['vd_rest_port'],
            'auth': glbl.admin.data['new_dir']['auth'] }
    olddir= {'vd_ip' :  glbl.admin.data['old_dir']['vd_ip'],
            'vd_rest_port': glbl.admin.data['old_dir']['vd_rest_port'],
            'auth': glbl.admin.data['old_dir']['auth'] }

    template_loader = jinja2.FileSystemLoader(searchpath=template_path)
    template_env = jinja2.Environment(loader=template_loader,undefined=jinja2.StrictUndefined)
    template_env.filters['jsonify'] = json.dumps
    dir_items = sorted(os.listdir(template_path))

    for i in dir_items:
       # check the format of the files
       if not re.match(r'^\d{3}_.+\.json$', i):
          continue
       _key = i[4:]
       if _key in fil:
          _val = fil[_key]
       else:
          if _key[0:3] == 'GET':
            fil[_key]=get_default
          else:
            fil[_key]=create_dns_config
          _val = fil[_key]
       #for _key,_val in fil.items():
       _ofile = transform_in(i)
       my_template = template_env.get_template(i)
       _newkey = _key.split(".")[0]
       #print("==============In %s==========" %(_newkey))
       mlog.warn("==============In {0}==========".format(_newkey))
       if _key[0:3] == 'GET':
         if _newkey == 'GET_RELEASE_INFO':
           x= my_template.render()
           y= json_loads(x)
           #_val(str(y['method']), str(y['path']), json.dumps(y['payload']),resp=str(y['response']),_name=None,_ofile=_ofile)
           _val(str(y['method']), str(y['path']), json.dumps(y['payload']),resp=str(y['response']),_name=None, vd_data=newdir,vd_data1=olddir,_ofile=_ofile)
         elif _newkey == 'GET_TIME_ZONE':
           x= my_template.render()
           y= json_loads(x)
           _val(str(y['method']), str(y['path']), json.dumps(y['payload']),resp=str(y['response']),_name=None,_ofile=_ofile)
         elif _newkey == 'GET_NTP_SERVER':
           x= my_template.render()
           y= json_loads(x)
           _val(str(y['method']), str(y['path']), json.dumps(y['payload']),resp=str(y['response']),_name=None,_ofile=_ofile)
         elif _newkey == 'GET_DNS_SERVER':
           x= my_template.render()
           y= json_loads(x)
           _val(str(y['method']), str(y['path']), json.dumps(y['payload']),resp=str(y['response']),_name=None,_ofile=_ofile)
         elif _newkey == 'GET_NMS_PROVIDER':
           x= my_template.render()
           y= json_loads(x)
           _val(str(y['method']), str(y['path']), json.dumps(y['payload']),resp=str(y['response']),_name=None,_ofile=_ofile)
         elif _newkey == 'GET_ANALYTICS_CLUSTER':
           x= my_template.render()
           y= json_loads(x)
           _val(str(y['method']), str(y['path']), json.dumps(y['payload']),resp=str(y['response']),_name=None,_ofile=_ofile)
         elif _newkey == 'GET_AUTH_CONNECTOR':
           x= my_template.render()
           y= json_loads(x)
           _val(str(y['method']), str(y['path']), json.dumps(y['payload']),resp=str(y['response']),_name=None,_ofile=_ofile)
         elif _newkey == 'GET_DEFAULT_AUTH_CONNECTOR':
           x= my_template.render()
           y= json_loads(x)
           _val(str(y['method']), str(y['path']), json.dumps(y['payload']),resp=str(y['response']),_name=None,_ofile=_ofile)
         elif _newkey == 'GET_AUTH_CONNECTOR_CONFIG':
           x= my_template.render()
           y= json_loads(x)
           _val(str(y['method']), str(y['path']), json.dumps(y['payload']),resp=str(y['response']),_name=None,_ofile=_ofile)
         elif _newkey == 'GET_SDWAN_WORKFLOW_LIST':
           x= my_template.render()
           y= json_loads(x)
           _val(str(y['method']), str(y['path']), json.dumps(y['payload']),resp=str(y['response']),_ofile=None)
         elif _newkey == 'GET_OLD_SDWAN_WORKFLOW_LIST':
           x= my_template.render()
           y= json_loads(x)
           _val(str(y['method']), str(y['path']), json.dumps(y['payload']),resp=str(y['response']),_ofile=None)
         elif _newkey == 'GET_CONTROLLER_WORKFLOW' or  _newkey == 'GET_PEER_CONTROLLER_WORKFLOW':
           if _newkey == 'GET_CONTROLLER_WORKFLOW': 
               _name = glbl.cntlr.data['new_cntlr'][0]["controllerName"]
           else: 
               _name = glbl.cntlr.data['new_cntlr'][1]["controllerName"]
           x= my_template.render(controllerName=_name)
           y= json_loads(x)
           _val(str(y['method']), str(y['path']), json.dumps(y['payload']),resp=str(y['response']),_ofile=_ofile)
         elif _newkey == 'GET_DEPLOY_CONTROLLER_WORKFLOW' or  _newkey == 'GET_DEPLOY_PEER_CONTROLLER_WORKFLOW':
           if _newkey == 'GET_DEPLOY_CONTROLLER_WORKFLOW': 
               _name = glbl.cntlr.data['new_cntlr'][0]["controllerName"]
           else: 
               _name = glbl.cntlr.data['new_cntlr'][1]["controllerName"]
           x= my_template.render(controllerName=_name)
           y= json_loads(x)
           _val(str(y['method']), str(y['path']), json.dumps(y['payload']),resp=str(y['response']),_name=_name,_ofile=_ofile)
         elif _newkey == 'GET_ORG_WORKFLOW':
           x= my_template.render(custName=glbl.cust.data["custName"])
           y= json_loads(x)
           _val(str(y['method']), str(y['path']), json.dumps(y['payload']),resp=str(y['response']),_name=glbl.cust.data["custName"],vd_data=newdir,vd_data1=olddir,_ofile=_ofile)
         elif _newkey == 'GET_CONTROLLER_CONFIG_BUILD' or _newkey == 'GET_PEER_CONTROLLER_CONFIG_BUILD':
           if _newkey == 'GET_CONTROLLER_CONFIG_BUILD': 
               _name = glbl.cntlr.data['new_cntlr'][0]["controllerName"]
           else: 
               _name = glbl.cntlr.data['new_cntlr'][1]["controllerName"]
           x= my_template.render(controllerName=_name)
           y= json_loads(x)
           _val(str(y['method']), str(y['path']), json.dumps(y['payload']),resp=str(y['response']),_name=_name,_ofile=_ofile)
         elif _newkey == 'GET_CONTROLLER_VNI' or _newkey == 'GET_PEER_CONTROLLER_VNI':
           if _newkey == 'GET_CONTROLLER_VNI': 
               _name = glbl.cntlr.data['new_cntlr'][0]["controllerName"]
           else: 
               _name = glbl.cntlr.data['new_cntlr'][1]["controllerName"]
           x= my_template.render(controllerName=_name)
           y= json_loads(x)
           _val(str(y['method']), str(y['path']), json.dumps(y['payload']),resp=str(y['response']),_name=_name,_ofile=_ofile)
         elif _newkey == 'GET_CONTROLLER_ROUTING' or _newkey == 'GET_PEER_CONTROLLER_ROUTING':
           if _newkey == 'GET_CONTROLLER_ROUTING': 
               _name = glbl.cntlr.data['new_cntlr'][0]["controllerName"]
           else: 
               _name = glbl.cntlr.data['new_cntlr'][1]["controllerName"]
           x= my_template.render(controllerName=_name)
           y= json_loads(x)
           _val(str(y['method']), str(y['path']), json.dumps(y['payload']),resp=str(y['response']),_name=_name,_ofile=_ofile)
         elif _newkey == 'GET_CONTROLLER_NTP'  or _newkey == 'GET_PEER_CONTROLLER_NTP':
           if _newkey == 'GET_CONTROLLER_NTP': 
               _name = glbl.cntlr.data['new_cntlr'][0]["controllerName"]
           else: 
               _name = glbl.cntlr.data['new_cntlr'][1]["controllerName"]
           x= my_template.render(controllerName=_name)
           y= json_loads(x)
           _val(str(y['method']), str(y['path']), json.dumps(y['payload']),resp=str(y['response']),_name=_name,_ofile=_ofile)
         elif _newkey == 'GET_CONTROLLER_OAM_ALARMS' or _newkey == 'GET_PEER_CONTROLLER_OAM_ALARMS':
           if _newkey == 'GET_CONTROLLER_OAM_ALARMS': 
               _name = glbl.cntlr.data['new_cntlr'][0]["controllerName"]
           else: 
               _name = glbl.cntlr.data['new_cntlr'][1]["controllerName"]
           x= my_template.render(controllerName=_name)
           y= json_loads(x)
           _val(str(y['method']), str(y['path']), json.dumps(y['payload']),resp=str(y['response']),_name=_name,_ofile=_ofile)
         elif _newkey == 'GET_CONTROLLER_ORG_SERVICES' or _newkey == 'GET_PEER_CONTROLLER_ORG_SERVICES':
           if _newkey == 'GET_CONTROLLER_ORG_SERVICES': 
               _name = glbl.cntlr.data['new_cntlr'][0]["controllerName"]
               option = 0
           else: 
               _name = glbl.cntlr.data['new_cntlr'][1]["controllerName"]
               option=1
           x= my_template.render(controllerName=_name)
           y= json_loads(x)
           _val(str(y['method']), str(y['path']), json.dumps(y['payload']),resp=str(y['response']),_name=_name, vd_data=newdir,vd_data1=olddir,_ofile=_ofile,option=option)
         elif _newkey == 'GET_CONTROLLER_ORG' or  _newkey == 'GET_PEER_CONTROLLER_ORG':
           if _newkey == 'GET_CONTROLLER_ORG': 
               _name = glbl.cntlr.data['new_cntlr'][0]["controllerName"]
           else: 
               _name = glbl.cntlr.data['new_cntlr'][1]["controllerName"]
           x= my_template.render(controllerName=_name)
           y= json_loads(x)
           _val(str(y['method']), str(y['path']), json.dumps(y['payload']),resp=str(y['response']),_name=_name,_ofile=_ofile)
         elif _newkey == 'GET_CONTROLLER_SYSTEM' or _newkey == 'GET_PEER_CONTROLLER_SYSTEM':
           if _newkey == 'GET_CONTROLLER_SYSTEM': 
               _name = glbl.cntlr.data['new_cntlr'][0]["controllerName"]
           else: 
               _name = glbl.cntlr.data['new_cntlr'][1]["controllerName"]
           x= my_template.render(controllerName=_name)
           y= json_loads(x)
           _val(str(y['method']), str(y['path']), json.dumps(y['payload']),resp=str(y['response']),_name=_name,_ofile=_ofile)
         elif _newkey == 'GET_CONTROLLER_COMMIT' or _newkey == 'GET_PEER_CONTROLLER_COMMIT':
           if _newkey == 'GET_CONTROLLER_COMMIT': 
               _name = glbl.cntlr.data['new_cntlr'][0]["controllerName"]
           else: 
               _name = glbl.cntlr.data['new_cntlr'][1]["controllerName"]
           x= my_template.render(controllerName=_name)
           y= json_loads(x)
           _val(str(y['method']), str(y['path']), json.dumps(y['payload']),resp=str(y['response']),_name=_name,_ofile=_ofile)
         elif _newkey == 'GET_CONTROLLER_SYNCH' or _newkey == 'GET_PEER_CONTROLLER_SYNCH':
           if _newkey == 'GET_CONTROLLER_SYNCH': 
               _name = glbl.cntlr.data['new_cntlr'][0]["controllerName"]
           else: 
               _name = glbl.cntlr.data['new_cntlr'][1]["controllerName"]
           x= my_template.render(controllerName=_name)
           y= json_loads(x)
           _val(str(y['method']), str(y['path']), json.dumps(y['payload']),resp=str(y['response']),_name=_name,_ofile=_ofile)
         elif _newkey == 'GET_DEVICE_GROUP':
           x= my_template.render(custName=glbl.cust.data["custName"])
           y= json_loads(x)
           _val(str(y['method']), str(y['path']), json.dumps(y['payload']),resp=str(y['response']),_name=glbl.cust.data["custName"],_ofile=_ofile)
         elif _newkey == 'GET_ORG_LIST':
           x= my_template.render()
           y= json_loads(x)
           _val(str(y['method']), str(y['path']), json.dumps(y['payload']),resp=str(y['response']),vd_data=newdir,vd_data1=olddir)
         elif _newkey == 'GET_RECOVERY_BACKUP':
           x= my_template.render()
           y= json_loads(x)
           if _val(str(y['method']), str(y['path']), json.dumps(y['payload']),resp=str(y['response']),vd_data=newdir,option=2):
              mlog.warn(bcolors.OKWARN + "Please use this backup to recover in case of disaster" + bcolors.ENDC)
             
           if _val(str(y['method']), str(y['path']), json.dumps(y['payload']),resp=str(y['response']),vd_data=olddir,option=1):
              mlog.warn(bcolors.OKWARN + "Please use this backup to restore on the on New Director " + bcolors.ENDC)
         elif _newkey == 'GET_CONTROLLER_CONFIG' or _newkey == 'GET_PEER_CONTROLLER_CONFIG':
          if _newkey == 'GET_CONTROLLER_CONFIG': 
            cname = glbl.cntlr.data['new_cntlr'][0]["controllerName"]
          else: 
            cname = glbl.cntlr.data['new_cntlr'][1]["controllerName"]
           x= my_template.render(cntlrName = cname)
           y= json_loads(x)
           _val(str(y['method']), str(y['path']), json.dumps(y['payload']),resp=str(y['response']),vd_data=olddir,option=2)

         else:
           x= my_template.render()
           y= json_loads(x)
           _val(str(y['method']), str(y['path']), json.dumps(y['payload']),resp=str(y['response']))

    mlog.warn(bcolors.OKWARN + "==============Completed ==========" + bcolors.ENDC)
    mlog.warn(bcolors.OKWARN + "Once the restore from backup is completed run the vnms-startup script.\n" +
              "Remember that the UI password will change to that of the Old Director" +
              "Disable the HA and re-enable HA with appropriate data.\n" + 
              "Proceed to run the next script.\n" + bcolors.ENDC)

if __name__ == "__main__":

  _cnt1 = 0
  if os.path.isfile("vmMigrate.log"):
    with open("vmMigrate.log","r") as fp:
      for _cnt1,line in enumerate(fp):
        pass
    fp.close()
    _cnt1 = _cnt1 + 1

  main()

  _errlog=""
  _cnt2 = 0
  if os.path.isfile("vmMigrate.log"):
    with open("vmMigrate.log","r") as fp:
      for _cnt2,line in enumerate(fp):
        if _cnt2 >= _cnt1:
          if re.search("ERROR -",line):
            _errlog = _errlog + line
    fp.close()
    if len( _errlog ) > 0:
      fp=open("vmphase1.err","w+")
      fp.write(_errlog)
      fp.close()
      if mlog:
        mlog.warn(bcolors.OKWARN + "Error log vmphase1.err is created since there were errors." + bcolors.ENDC)


