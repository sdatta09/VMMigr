#!/usr/bin/env python3

import os, sys, signal, argparse
import jinja2
from jinja2.utils import concat
import re
import requests
import time
import base64
import xmltodict
#import subprocess
import json
from pprint import pprint
from collections import OrderedDict
#import uuid
from pprint import pprint
import logging
import logging.handlers
import copy
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
NOT_DEPLOYED = 0 
MYLINES = 0
MYCOL = 0

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
  parser.add_argument('-r','--read',required=False, action='store_true', help='input file [required ]' )
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
    To re-read input data :
      %(mystr)s -f vm_phase3.json -r  [ Note : the file MUST be vm_phase3.json and NOT vm_phase2.json ]
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



def find_wan( _str):
  if _str in glbl.vnms.data['wanNtwk']:
    return glbl.vnms.data['wanNtwk'][_str]
  else:
    return None


def create_controller( _method, _uri,_payload,resp='200', name="Controller"):
    global vnms, analy, cntlr, cust, mlog
    mlog.info("In function " + create_controller.__name__)
    mlog.warn(bcolors.OKWARN + "Have you performed a erase config on the controller: {0} and verified that services are running.\nIf not do so now".format(name) + bcolors.ENDC)
    ret = yes_or_no2("Continue: " )
    if ret == 0  or ret == 2 : return
    resp = '200'
    vdict = {}
    vdict = {'body': _payload, 'resp': resp, 'method': _method, 'uri': _uri}
    [status, resp_str] = common.call(vdict,content_type='json',ncs_cmd="no")
    if status == 1:
      mlog.warn("Creation of New Controller = {0} sucessful ".format(name))
      if len (resp_str) > 3 :
        newjstr = json_loads(resp_str)
        mlog.info("Return json from POST on Controller: {0} = {1}".format(name,json.dumps(newjstr,indent=4)))
    else:
      mlog.error("Creation of New Controller = {0} NOT sucessful ".format(name))
      sys.exit("Creation of New Controller = {0} NOT sucessful ".format(name))

    # the below is payload of the POST not the response
    jstr = json_loads(_payload)
    mycntlr = None
    for mcntlr in glbl.cntlr.data['new_cntlr']:
      if mcntlr["controllerName"] == name:
        mycntlr = mcntlr
        break
    if mycntlr is None:
      mlog.error("Can not find controller: {0} in my list ".format(name))
      sys.exit("Can not find controller: {0} in my list ".format(name))

    # from the GET we need to save the public ip address of the controller. this is needed in phase 3
    if "versanms.sdwan-controller-workflow" in jstr:
      if "peerControllers" in jstr["versanms.sdwan-controller-workflow"]: 
        mycntlr["peerControllers"] =  []
        mycntlr["peerControllers"] =  jstr["versanms.sdwan-controller-workflow"]["peerControllers"]
      if "baremetalController" in jstr["versanms.sdwan-controller-workflow"] and "wanInterfaces" in jstr["versanms.sdwan-controller-workflow"]["baremetalController"] :
        wanlist =  jstr["versanms.sdwan-controller-workflow"]["baremetalController"]["wanInterfaces"]
        for wan in wanlist:
          if "unitInfoList" in wan:
            unitinfoList = wan["unitInfoList"] 
            for unitinfo in unitinfoList:
              if "networkName" in unitinfo:
                x = find_wan(unitinfo["networkName"]) 
                if x and x == "Internet" and "publicIPAddress" in unitinfo:
                  mycntlr["inet_public_ip_address"] = unitinfo["publicIPAddress"]
                elif x and x == "MPLS" and "ipv4address" in unitinfo:
                  y = unitinfo["ipv4address"]
                  mycntlr["mpls_public_ip_address"] = y[0].rsplit("/")[0]
                else:
                  mlog.warn("Getting unknown Ntwk Name = {0}".format(unitinfo["networkName"])) 

    write_outfile(glbl.vnms,glbl.analy,glbl.cntlr,glbl.cust, glbl.admin)
    return

def get_default( _method, _uri,_payload,resp='200', ofile=None):
    global vnms, analy, cntlr, cust, mlog
    vdict = {}
    mlog.info("In function " + get_default.__name__)
    vdict = {'body': _payload, 'resp': resp, 'method': _method, 'uri': _uri}
    [out, resp_str] = common.call(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
    jstr = json_loads(resp_str)
    print(jstr)
    if ofile is None: 
       mlog.error("No file provided .. exiting")
       sys.exit("No file provided .. exiting")
    out = common.create_out_data("POST","200","/vnms/sdwan/workflow/controllers/controller", jstr)
    fp=open(ofile,"w+")
    out1 = json.dumps(out, indent=4)
    fp.write(out1)
    fp.close()
    return

def create_controller_build( _method, _uri,_payload,resp='202',name="Controller"):
    global vnms, analy, cntlr, cust, mlog
    vdict = {}
    mlog.info("In function " + create_controller_build.__name__)
    [status, resp_str] = common.check_controller_status(name=name)
    if status == 1 and len(resp_str) > 3:
       jstr = json_loads(resp_str)
       if "syncStatus" in jstr and jstr["syncStatus"] == "IN_SYNC":
          mlog.info("Controller {0} is in sync ".format(name))
          vdict = {'body': _payload, 'resp': resp, 'method': _method, 'uri': _uri}
          common.call(vdict,content_type='json',ncs_cmd="no")
       else: 
          mlog.error ("Controller {0} is NOT in sync -- Exiting ".format(name))
          sys.exit("Controller {0} is NOT in sync -- Exiting ".format(name))
    else:
        mlog.error ("Did not get correct resp for Controller {0} is NOT in sync -- Exiting ".format(name))
        sys.exit("Did not get correct resp for Controller {0} is NOT in sync -- Exiting ".format(name))
    return 

def deploy_controller( _method, _uri,_payload,resp='202',name="Controller"):
    global vnms, analy, cntlr, cust, mlog
    vdict = {}
    mlog.info("In function " + deploy_controller.__name__)
    vdict = {'body': _payload, 'resp': resp, 'method': _method, 'uri': _uri}
    [status, resp_str] = common.call(vdict,content_type='json', max_retry_for_task_completion=50, ncs_cmd="no")
    if status == 1:
      mlog.warn("Deploy of New Controller = {0} sucessful ".format(name))
      if len (resp_str) > 3 :
        newjstr = json_loads(resp_str)
        mlog.info("Return json from Deploy POST on Controller: {0} = {1}".format(name,json.dumps(newjstr,indent=4)))
    else:
      mlog.error("Deploy of New Controller = {0} NOT sucessful ".format(name))
      sys.exit("Deploy of New Controller = {0} NOT sucessful ".format(name))
    # Now we need to check the status
    mlog.warn("Checking Status of New Controller = {0}. Please be patient".format(name))
    found = 0
    for i in range(0,5):
      time.sleep(5)
      [out,resp_str] = common.check_controller_status(name=name)
      if out == 1 and len(resp_str) > 3:
        jstr = json_loads(resp_str)
        if "syncStatus" in jstr and jstr["syncStatus"] == "IN_SYNC":                      
          mlog.warn("New Controller = {0} in Sync. ".format(name))
          found = 1
          break

    if found == 0:
      mlog.error("Controller not in proper state for Controller: {0}".format(name))
      sys.exit("Controller not in proper state for Controller: {0}".format(name))

    return 

def get_dir_release_info ( _method, _uri, _payload,resp='200', _name=None,_ofile=None):
    global vnms, analy, cntlr, cust, admin, mlog
    mlog.info("In function " + get_dir_release_info.__name__)
    resp2 = '202'
    vdict = {}
    vdict = {'body': _payload, 'resp': resp, 'resp2': resp2, 'method': _method, 'uri': _uri}
    [out, resp_str] = common.call(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
    if len(resp_str) > 3:
        jstr = json_loads(resp_str)
        mlog.info("Release Info list = {0}".format(json.dumps(jstr,indent=4)))
        if "package-info" in jstr:
           if ("major-version" in jstr["package-info"][0] and "minor-version" in jstr["package-info"][0] 
                   and "service-version" in jstr["package-info"][0]):
               newstr =  jstr["package-info"][0]["major-version"] + "." \
                                    + jstr["package-info"][0]["minor-version"] + "." \
                                    + jstr["package-info"][0]["service-version"] 
               if newstr != glbl.vnms.data["rel"]:
                  mlog.error("Release data does not match")
                  sys.exit("Release data does not match")
               else:
                  mlog.info("Release data matches")
        elif "error" in jstr and jstr["error"]['http_status_code'] == 401 :
          mlog.error("This is most likely a password issue. Please change in input json file: vm_phase2.json and re-run")
          sys.exit("This is most likely a password issue. Please change in input json file: vm_phase2.json and re-run")
        else : 
          mlog.error("This is most likely a password issue. Please change in input json file: vm_phase2.json and re-run")
          sys.exit("This is most likely a password issue. Please change in input json file: vm_phase2.json and re-run")
    else:
        mlog.error("This is most likely a password issue. Please change in input json file: vm_phase2.json and re-run")
        sys.exit("This is most likely a password issue. Please change in input json file: vm_phase2.json and re-run")
    return ''

def get_dir_time_zones ( _method, _uri, _payload,resp='200', _name=None,_ofile=None):
    global vnms, analy, cntlr, cust, mlog
    mlog.info("In function {0} with outfile={1}".format(get_dir_time_zones.__name__,_ofile))
    resp2 = '202'
    vdict = {}
    # first we delete and then create
    vdict = {'body': _payload, 'resp': resp, 'resp2': resp2, 'method': "DELETE", 'uri': _uri}
    mlog.info("Deleting in {0}".format(get_dir_time_zones.__name__))
    [out, resp_str] = common.call(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
    if len(resp_str) > 3:
      jstr = json_loads(resp_str)
      mlog.info("Time Zone = {0}".format(json.dumps(jstr,indent=4)))
    vdict = {'body': _payload, 'resp': resp, 'resp2': resp2, 'method': _method, 'uri': _uri}
    mlog.info("Creating in {0}".format(get_dir_time_zones.__name__))
    [out, resp_str] = common.call(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
    if len(resp_str) > 3:
      jstr = json_loads(resp_str)
      mlog.info("Timezone Info = {0}".format(json.dumps(jstr,indent=4)))
    return ''

def get_dir_ntp_server ( _method, _uri, _payload,resp='200', _name=None,_ofile=None):
    global vnms, analy, cntlr, cust, mlog
    mlog.info("In function {0} with outfile={1}".format(get_dir_ntp_server.__name__,_ofile))
    resp2 = '202'
    vdict = {}
    vdict = {'body': _payload, 'resp': resp, 'resp2': resp2, 'method': "DELETE", 'uri': _uri}
    mlog.info("Deleting in {0}".format(get_dir_ntp_server.__name__))
    [out, resp_str] = common.call(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
    if len(resp_str) > 3:
      jstr = json_loads(resp_str)
      mlog.info("NTP info = {0}".format(json.dumps(jstr,indent=4)))
    vdict = {'body': _payload, 'resp': resp, 'resp2': resp2, 'method': _method, 'uri': _uri}
    [out, resp_str] = common.call(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
    if len(resp_str) > 3:
      jstr = json_loads(resp_str)
      mlog.info("NTP Info = {0}".format(json.dumps(jstr,indent=4)))
    return ''

def get_dir_dns_server ( _method, _uri, _payload,resp='200', _name=None,_ofile=None):
    global vnms, analy, cntlr, cust, mlog
    mlog.info("In function {0} with outfile={1}".format(get_dir_dns_server.__name__,_ofile))
    resp2 = '202'
    vdict = {}
    dnspayload = {"dns": {}}
    dnspayloadstr =json.dumps(dnspayload) 
    vdict = {'body': dnspayloadstr , 'resp': resp, 'resp2': resp2, 'method': "PUT", 'uri': _uri}
    mlog.info("Deleting in {0}".format(get_dir_dns_server.__name__))
    [out, resp_str] = common.call(vdict,content_type='json',ncs_cmd="yes",jsonflag=1)
    if len(resp_str) > 3:
      jstr = json_loads(resp_str)
      mlog.info("DNS Info after PUT = {0}".format(json.dumps(jstr,indent=4)))
    vdict = {'body': _payload, 'resp': resp, 'resp2': resp2, 'method': _method, 'uri': _uri}
    [out, resp_str] = common.call(vdict,content_type='json',ncs_cmd="yes",jsonflag=1)
    if len(resp_str) > 3:
      jstr = json_loads(resp_str)
      mlog.info("DNS Info = {0}".format(json.dumps(jstr,indent=4)))
    return ''

# this is primarily to check that NEW Director is NOT able to connect to OLD Controller
# Do not use this function anywhere
def controller_connect(device):
    global vnms, analy, cntlr, cust, admin, auth, debug, mlog
    resp = '200'
    resp2 = '202'
    _uri = "/api/config/devices/device/" + device["name"] + "/_operations/connect"
    _payload = {}
    vdict = {}
    vdict = {'body': _payload, 'resp': resp, 'resp2': resp2, 'method': "POST", 'uri': _uri }

    [out, resp_str] = common.call(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
    if out == 1 and len(resp_str) > 3:
      jstr = json_loads(resp_str)
      if "output" in jstr and "result" in  jstr["output"] and jstr["output"]["result"] == 0: 
        mlog.warn("No connection from new Director to contoller={0} -- Good! Any previous errors can be ignored ".format(device["name"]))
        return True
      else:
        return False
    else:
      mlog.warn("No connection from new Director to contoller={0} -- Good! Any previous errors can be ignored ".format(device["name"]))
      return True

def set_nms_provider( _method, _uri, _payload,resp='200', _name=None,_ofile=None):
    global vnms, analy, cntlr, cust, mlog
    mlog.info("In function {0} with outfile={1}".format(set_nms_provider.__name__,_ofile))
    resp2 = '202'
    vdict = {}
    # before we do this step lets delete the default auth connector
    mlog.info("In function {0} Deleting default auth-connector".format(set_nms_provider.__name__))
    payload1 = {}
    uri1 = '/api/config/nms/provider/default-auth-connector'
    vdict = {'body': payload1, 'resp': resp, 'resp2': resp2, 'method': "DELETE", 'uri': uri1}
    [out, resp_str] = common.call(vdict,content_type='json',ncs_cmd="yes",jsonflag=1)
    if len(resp_str) > 3:
      jstr = json_loads(resp_str)
      pprint(jstr)
      mlog.info("NMS Info after DELETE = {0}".format(json.dumps(jstr,indent=4)))
    #return ''
    vdict = {'body': _payload, 'resp': resp, 'resp2': resp2, 'method': _method, 'uri': _uri}
    [out, resp_str] = common.call(vdict,content_type='json',ncs_cmd="yes",jsonflag=1)
    if len(resp_str) > 3:
      jstr = json_loads(resp_str)
      mlog.info("NMS Info after PUT = {0}".format(json.dumps(jstr,indent=4)))
    return ''

def get_dir_analytics_cluster ( _method, _uri, _payload,resp='200', _name=None,_ofile=None):
    global vnms, analy, cntlr, cust, mlog
    mlog.info("In function {0} with outfile={1}".format(get_dir_analytics_cluster.__name__,_ofile))
    resp2 = '202'
    vdict = {}
    vdict = {'body': _payload, 'resp': resp, 'resp2': resp2, 'method': "DELETE", 'uri': _uri}
    mlog.info("Deleting in {0}".format(get_dir_analytics_cluster.__name__))
    [out, resp_str] = common.call(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
    if len(resp_str) > 3:
      jstr = json_loads(resp_str)
      mlog.info("Analytic Cluster ater DELETE = {0}".format(json.dumps(jstr,indent=4)))
    vdict = {'body': _payload, 'resp': resp, 'resp2': resp2, 'method': _method, 'uri': _uri}
    [out, resp_str] = common.call(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
    if len(resp_str) > 3:
      jstr = json_loads(resp_str)
      mlog.info("Analytic Cluster = {0}".format(json.dumps(jstr,indent=4)))
    return ''

def get_dir_auth_connector ( _method, _uri, _payload,resp='200', _name=None,_ofile=None):
    global vnms, analy, cntlr, cust, mlog
    mlog.info("In function {0} with outfile={1}".format(get_dir_auth_connector.__name__,_ofile))
    resp2 = '202'
    vdict = {}
    vdict = {'body': _payload, 'resp': resp, 'resp2': resp2, 'method': "DELETE", 'uri': _uri}
    mlog.info("Deleting in {0}".format(get_dir_auth_connector.__name__))
    [out, resp_str] = common.call(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
    if len(resp_str) > 3:
      jstr = json_loads(resp_str)
      pprint(jstr)
    mlog.info("Create in {0}".format(get_dir_auth_connector.__name__))
    vdict = {'body': _payload, 'resp': resp, 'resp2': resp2, 'method': _method, 'uri': _uri}
    [out, resp_str] = common.call(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
    if len(resp_str) > 3:
      jstr = json_loads(resp_str)
      pprint(jstr)
    return ''

def get_dir_default_auth_connector ( _method, _uri, _payload,resp='200', _name=None,_ofile=None):
    global vnms, analy, cntlr, cust, mlog
    mlog.info("In function {0} with outfile={1}".format(get_dir_default_auth_connector.__name__,_ofile))
    resp2 = '202'
    vdict = {}
    vdict = {'body': _payload, 'resp': resp, 'resp2': resp2, 'method': _method, 'uri': _uri}
    [out, resp_str] = common.call(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
    if len(resp_str) > 3:
      jstr = json_loads(resp_str)
      pprint(jstr)
    return ''

def get_dir_auth_connector_config ( _method, _uri, _payload,resp='200', _name=None,_ofile=None):
    global vnms, analy, cntlr, cust, mlog
    mlog.info("In function {0} with outfile={1}".format(get_dir_auth_connector_config.__name__,_ofile))
    resp2 = '202'
    vdict = {}
    vdict = {'body': _payload, 'resp': resp, 'resp2': resp2, 'method': _method, 'uri': _uri}
    [out, resp_str] = common.call(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
    if len(resp_str) > 3:
      jstr = json_loads(resp_str)
      pprint(jstr)
    return ''


def deploy_org_workflow( _method, _uri, _payload,resp='200', name=None,_ofile=None):
    global vnms, analy, cntlr, cust, mlog
    mlog.info("In function {0} with outfile={1}".format(deploy_org_workflow.__name__,_ofile))
    resp2 = '202'
    if name is None:
      mlog.error("Can not continue without Customer Name ")
      sys.exit("Can not continue without Customer Name ")
    vdict = {}
    payload1 = {}
    mlog.info("In function {0} calling Get ".format(deploy_org_workflow.__name__))
    vdict = {'body': payload1, 'resp': resp, 'resp2': resp2, 'method': "GET", 'uri': _uri}
    [out, resp_str] = common.call(vdict,content_type='json',ncs_cmd="no",max_retry_for_task_completion=50,jsonflag=1)
    if out == 1:
      mlog.warn("Deploy of org workflow successful")
    if len(resp_str) > 3:
      jstr = json_loads(resp_str)
      orig_jstr = json_loads(_payload)
      if "versanms.sdwan-org-workflow" in jstr:
         # we need to copy the controller and the Analytics data from newdir to olddir
         # and not the reverse way
         if "controllers" in orig_jstr["versanms.sdwan-org-workflow"]:
           jstr["versanms.sdwan-org-workflow"]["controllers"] = []
           jstr["versanms.sdwan-org-workflow"]["controllers"] = orig_jstr["versanms.sdwan-org-workflow"]["controllers"]
         else:
           mlog.error("No controller information -- can not continue. In function {0}".format(deploy_org_workflow.__name__))
           sys.exit("No controller information -- can not continue. In function {0}".format(deploy_org_workflow.__name__))
         if "analyticsClusters" in orig_jstr["versanms.sdwan-org-workflow"]:
           jstr["versanms.sdwan-org-workflow"]["analyticsClusters"] = []
           jstr["versanms.sdwan-org-workflow"]["analyticsClusters"] = orig_jstr["versanms.sdwan-org-workflow"]["analyticsClusters"]
         else:
           mlog.error("No Analytics information -- can not continue. In function {0}".format(deploy_org_workflow.__name__))
           sys.exit("No Analytics information -- can not continue. In function {0}".format(deploy_org_workflow.__name__))
         _newpayload = json.dumps(jstr) 
         vdict = {'body': _newpayload, 'resp': resp, 'resp2': resp2, 'method': _method, 'uri': _uri}
         mlog.info("In function {0} calling PUT ".format(deploy_org_workflow.__name__))
         [out, resp_str] = common.call(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
         if len(resp_str) > 3:
            jstr = json_loads(resp_str)
            pprint(jstr)
         _newuri = '/vnms/sdwan/workflow/orgs/org/deploy/' + name
         vdict = {'body': _newpayload, 'resp': resp, 'resp2': resp2, 'method': "POST" , 'uri': _newuri}
         mlog.info("In function {0} calling POST ".format(deploy_org_workflow.__name__))
         [out, resp_str] = common.call(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
         if len(resp_str) > 3:
            jstr = json_loads(resp_str)
            pprint(jstr)
    return ''
   
def get_sdwan_workflow_list( _method, _uri, _payload,resp='200', _ofile=None):
    global vnms, analy, cntlr, cust, mlog
    resp2 = '202'
    vdict = {}
    mlog.info("In function {0} ".format(get_sdwan_workflow_list.__name__))
    vdict = {'body': _payload, 'resp': resp, 'resp2': resp2, 'method': _method, 'uri': _uri}
    [out, resp_str] = common.call(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
    if out == 1 and len(resp_str) > 3:
      jstr = json_loads(resp_str)
      if "versanms.sdwan-controller-list" in jstr:
        if len(jstr["versanms.sdwan-controller-list"]) == 0 or len(jstr["versanms.sdwan-controller-list"]) > 2 :
            print("Something wrong")
            mlog.error("Number of Controllers bad = {0} in return .. exiting".format(len(jstr["versanms.sdwan-controller-list"])))
            sys.exit("Number of Controllers bad = {0} in return .. exiting".format(len(jstr["versanms.sdwan-controller-list"])))
        else:
           glbl.cntlr.data['new_cntlr'].append( jstr["versanms.sdwan-controller-list"][0])
           glbl.cntlr.data['new_cntlr'].append( jstr["versanms.sdwan-controller-list"][1])
           #if debug : pprint(glbl.cntlr.data)
           write_outfile(glbl.vnms,glbl.analy,glbl.cntlr,glbl.cust, glbl.admin)
    return ''

def  deploy_template_workflow(dev):
      global vnms, analy, cntlr, cust, mlog
      mlog.warn("Deploying Template Workflow: {0}".format(dev["poststaging-template"]))
      resp = '200'
      resp2 = '202'
      vdict = {}
      _payload = {}
      _uri = "/vnms/sdwan/workflow/templates/template/" +  dev["poststaging-template"]
      vdict = {'body': _payload, 'resp': resp, 'resp2': resp2, 'method': "GET", 'uri': _uri}
      [out, resp_str] = common.call(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
      if out == 1 and len(resp_str) > 3:
        jstr = json_loads(resp_str)
        if "versanms.sdwan-template-workflow" in jstr and "templateName" in  jstr["versanms.sdwan-template-workflow"]:
          if dev["poststaging-template"] not in jstr["versanms.sdwan-template-workflow"]["templateName"]:
            mlog.warn("This is a HA template with template={0} with template={1}".format(dev["poststaging-template"],jstr["versanms.sdwan-template-workflow"]["templateName"]))
            dev["deployed"] = ""
            dev["deployed"] = "1"
            return True
        if "versanms.sdwan-template-workflow" in jstr and "controllers" in  jstr["versanms.sdwan-template-workflow"]:
          cntlr_list = [glbl.cntlr.data['new_cntlr'][0]["controllerName"], glbl.cntlr.data['new_cntlr'][1]["controllerName"]]
          jstr["versanms.sdwan-template-workflow"]["controllers"]= cntlr_list 
          vdict = {}
          _payload = json.dumps(jstr)
          _uri = "/vnms/sdwan/workflow/templates/template/" + dev["poststaging-template"]
          vdict = {'body': _payload, 'resp': resp, 'resp2': resp2, 'method': "PUT", 'uri': _uri}
          [out, resp_str] = common.call(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
          if out == 0:
            mlog.error("Workflow template PUT deploy = {0} was NOT successful".format(dev["poststaging-template"]))
            dev["deployed"] = ""
            dev["deployed"] = "0"
            if "redundantPair" in jstr["versanms.sdwan-template-workflow"]:
              dev["redundantPair_templ"] = ""
              dev["redundantPair_templ"] = jstr["versanms.sdwan-template-workflow"]["redundantPair"]["templateName"]
            return False
            #GET_OLD
            #GET_NEW
            #MODIFY
            #PATCH
          # Now the deploy
          newpayload = {}
          _uri = "/vnms/sdwan/workflow/templates/template/deploy/" +  dev["poststaging-template"]
          vdict = {'body': newpayload, 'resp': resp, 'resp2': resp2, 'method': "POST", 'uri': _uri}
          [out, resp_str] = common.call(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
          if out == 0:
            mlog.error("Deploy Template Workflow POST = {0} was NOT successful".format(dev["poststaging-template"]))
            dev["deployed"] = ""
            dev["deployed"] = "0"
            if "redundantPair" in jstr["versanms.sdwan-template-workflow"]:
              dev["redundantPair_templ"] = ""
              dev["redundantPair_templ"] = jstr["versanms.sdwan-template-workflow"]["redundantPair"]["templateName"]
            return False
          else:
            mlog.info("Deploy Template Workflow = {0} was successful".format(dev["poststaging-template"]))
            dev["deployed"] = ""
            dev["deployed"] = "1"
            return True
      else: 
        # the template for a paired device 
        # will need to figure out how to deal with these
        mlog.info("Deploy Template Workflow = {0} was not successful".format(dev["poststaging-template"]))
        dev["deployed"] = ""
        dev["deployed"] = "0"
        return False
      return True

def get_vnf_manager(device):
    global vnms, analy, cntlr, cust, mlog

    if device is None: 
      mlog.error("Bad inputs in function {0}. Input File is None ".format(get_vnf_manager.__name__))
      return

    mlog.info("In function {0} with device = {1} ".format(get_vnf_manager.__name__, device["name"]))
    resp = '200'
    resp2 = '202'
    _uri =  "/api/config/devices/template/" + device["poststaging-template"] + "/config/system/vnf-manager"
    _payload = {}
    vdict = {}
    vdict = {'body': _payload , 'resp': resp, 'resp2': resp2, 'method': "GET", 'uri': _uri}
    [out, resp_str] = common.call(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
    if out == 1 and len(resp_str) > 3:
      south_ip = [i['director_southIP'] + "/32" for i in glbl.vnms.data['director']]
      domain_ips = glbl.vnms.data['domain_ips']
      #print("S IP = " + " ".join(south_ip))
      jstr = json_loads(resp_str)
      #mlog.info("VNF Manager Info = {0}".format(json.dumps(jstr,indent=4)))
      if "vnf-manager" in jstr and "ip-addresses" in jstr["vnf-manager"]:
        #x= jstr["vnf-manager"]["ip-addresses"] + south_ip 
        jstr["vnf-manager"]["ip-addresses"] = []
        jstr["vnf-manager"]["ip-addresses"] = south_ip + domain_ips
        del jstr["vnf-manager"]["vnf-manager"]
        payload = json.dumps(jstr)
        vdict = {'body': payload , 'resp': resp, 'resp2': resp2, 'method': "PUT", 'uri': _uri}
        [out, resp_str] = common.call(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
        if len(resp_str) > 3:
          jstr = json_loads(resp_str)
          mlog.info("VNF Manager after PUT = {0}".format(json.dumps(jstr,indent=4)))
    return ''

def create_dns_config( _method, _uri,_payload,resp='200'):
    vdict = {}
    vdict = {'body': _payload, 'resp': resp, 'method': _method, 'uri': _uri}
    [out, resp_str] = common.call(vdict,content_type='json',ncs_cmd="no")
    if len(resp_str) > 3:
      jstr = json_loads(resp_str)
      mlog.info("Response = {0}".format(json.dumps(jstr,indent=4)))
    return ''

def  deploy_device_workflow(dev):
      global vnms, analy, cntlr, cust, mlog
      mlog.warn("Deploy Device Workflow for device: {0}".format(dev["name"]))
      resp = '200'
      resp2 = '202'
      vdict = {}
      _uri = "/vnms/sdwan/workflow/devices/device/" + dev["name"]
      _payload = {}
      vdict = {'body': _payload , 'resp': resp, 'resp2': resp2, 'method': "GET", 'uri': _uri}
      [out, resp_str] = common.call(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
      if out == 1 and len(resp_str) > 3:
        jstr = json_loads(resp_str)
        for mcntlr in glbl.cntlr.data['new_cntlr']:
          a = jstr['versanms.sdwan-device-workflow']['postStagingTemplateInfo']['templateData']['device-template-variable']['variable-binding']['attrs']
          local_auth_key = '{$v_'+ glbl.cust.data["custName"] + '_' + mcntlr["controllerName"] + '_Local_auth_email_key__IKELKey}'
          local_auth_identity = '{$v_'+ glbl.cust.data["custName"] + '_' + mcntlr["controllerName"] + '_Local_auth_email_identifier__IKELIdentifier}'
          for val in a:
            #print val
            if "name" in val and val["name"] == local_auth_key :
              if "peerControllers" in mcntlr:
                dev["local_auth_key"] = ""
                dev["local_auth_key"] = val["value"]
              else: 
                dev["local1_auth_key"] = ""
                dev["local1_auth_key"] = val["value"]
            elif "name" in val and val["name"] == local_auth_identity :
              if "peerControllers" in mcntlr:
                dev["local_auth_identity"] = ""
                dev["local_auth_identity"] = val["value"]
              else: 
                dev["local1_auth_identity"] = ""
                dev["local1_auth_identity"] = val["value"]
          if "peerControllers" in mcntlr:
            dev["remote_auth_identity"] = ""
            dev["remote_auth_identity"] = mcntlr["controllerName"] + '@' +  glbl.cust.data["custName"] + '.com' 
          else: 
            dev["remote1_auth_identity"] = ""
            dev["remote1_auth_identity"] = mcntlr["controllerName"] + '@' +  glbl.cust.data["custName"] + '.com' 

        # the above for the cntlr loop has ended here
        vdict = {'body': resp_str , 'resp': resp, 'resp2': resp2, 'method': "PUT", 'uri': _uri}
        [out, resp_str] = common.call(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
        if out == 1:
          mlog.info("Deploy Device Workflow PUT was successful for device: {0}".format(dev["name"]))
          time.sleep(10)
          _uri = "/vnms/sdwan/workflow/devices/device/deploy/" + dev["name"]
          _payload = {}
          vdict = {'body': _payload , 'resp': resp, 'resp2': resp2, 'method': "POST", 'uri': _uri}
          [ret, resp_str] = common.call(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
          if ret == 1:
            mlog.info("Deploy Device Workflow POST was successful for device: {0}".format(dev["name"]))
            # before we return back we need to change the VNF Manager in the device template on the new director
            dev["deployed"] = ""
            dev["deployed"] = "1"
            get_vnf_manager(dev)
            return True
          else: 
            mlog.error("Deploy Device Workflow POST was NOT successful for device: {0}".format(dev["name"]))
            dev["deployed"] = ""
            dev["deployed"] = "0"
            return False
        else: 
            mlog.error("Deploy Device Workflow PUT was NOT successful for device: {0}".format(dev["name"]))
            dev["deployed"] = ""
            dev["deployed"] = "0"
            return False
      else: 
        mlog.error("Deploy Device Workflow GET was NOT successful for device: {0}".format(dev["name"]))
        dev["deployed"] = ""
        dev["deployed"] = "0"
        return False
     
def get_device_group_new( _method, _uri, _payload,resp='200', _name=None,_ofile=None):
    global vnms, analy, cntlr, cust, mlog
    resp2 = '202'
    vdict = {}
    mlog.info("In function {0} ".format(get_device_group_new.__name__))
    count = 0
    totalcnt = -1
    errorlist = list(filter(lambda x: "deployed" in x and (x['deployed'] != "1"), glbl.vnms.data["devices"]))
    found = 0
    while 1:
      newuri = _uri + "&offset={0}&limit=25".format(count) 
      vdict = {'body': _payload, 'resp': resp, 'resp2': resp2, 'method': _method, 'uri': newuri}
      [out, resp_str] = common.call(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
      if out == 1 and len(resp_str) > 3:
        jstr = json_loads(resp_str)
        if count == 0 and totalcnt == -1:
          if "totalCount" in jstr: totalcnt = int(jstr["totalCount"])
          else: sys.exit("did not get totalCount")
        if "device-group" in jstr:
          for i in range(len(jstr["device-group"])):
            if ("inventory-name" in jstr["device-group"][i] and "poststaging-template" in jstr["device-group"][i] and 
                 len(jstr["device-group"][i]["inventory-name"]) > 0 ) : 
              for devname in jstr["device-group"][i]["inventory-name"]:
                for j in range( len( errorlist)):
                  if devname == errorlist[j]["name"]:
                    mlog.info("Found device in list {0} ".format(devname))
                    found = found + 1
                    
        if totalcnt <= (count + 25): break
        else: count = count + 25
    # Now we need to  a) delete the devices that do not have a post-staging template
    # b) deploy the device templates with the Controller info
    #if found != len(errorlist):
    #  mlog.warn("Found {0:d} devices while we should have {1:d} in such a state".format(found,len(errorlist)))
    #  sys.exit("Found {0:d} devices while we should have {1:d} in such a state".format(found,len(errorlist)))

    # for each of the devices call the template workflow and the device workflow
    workflow_template_list = []
    for dev in errorlist:
      if dev["poststaging-template"] not in workflow_template_list:
        if deploy_template_workflow(dev) :
          workflow_template_list.append(dev["poststaging-template"])
          #deploy_device_workflow(dev)
      else:
        # the workflow template has already been deployed sucessfully
        deploy_device_workflow(dev)

    write_outfile(glbl.vnms,glbl.analy,glbl.cntlr,glbl.cust, glbl.admin)
    return ''
    
     
def get_device_group( _method, _uri, _payload,resp='200', _name=None,_ofile=None):
    global vnms, analy, cntlr, cust, mlog
    resp2 = '202'
    vdict = {}
    mlog.info("In function {0} ".format(get_device_group.__name__))
    count = 0
    totalcnt = -1
    while 1:
      newuri = _uri + "&offset={0}&limit=25".format(count) 
      vdict = {'body': _payload, 'resp': resp, 'resp2': resp2, 'method': _method, 'uri': newuri}
      [out, resp_str] = common.call(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
      if out == 1 and len(resp_str) > 3:
        jstr = json_loads(resp_str)
        if count == 0 and totalcnt == -1:
          if "totalCount" in jstr: totalcnt = int(jstr["totalCount"])
          else: sys.exit("did not get totalCount")
        if "device-group" in jstr:
          if len(jstr["device-group"]) <= 0 : 
            sys.exit("Got 0 devices in device group")
          for i in range(len(jstr["device-group"])):
            if ("inventory-name" in jstr["device-group"][i] and "poststaging-template" in jstr["device-group"][i] and 
                 len(jstr["device-group"][i]["inventory-name"]) > 0 ) : 
              for devname in jstr["device-group"][i]["inventory-name"]:
                for j in range( len(glbl.vnms.data['devices'])):
                  if devname == glbl.vnms.data['devices'][j]["name"]:
                    mlog.info("Found device in list {0} ".format(devname))
                    glbl.vnms.data['devices'][j]["poststaging-template"] = ""
                    glbl.vnms.data['devices'][j]["dg-group"] = ""
                    glbl.vnms.data['devices'][j]["poststaging-template"] = jstr["device-group"][i]["poststaging-template"]
                    glbl.vnms.data['devices'][j]["dg-group"] = jstr["device-group"][i]["name"]
                    glbl.vnms.data['devices'][j]["deployed"] = ""
                    glbl.vnms.data['devices'][j]["deployed"] = "0"
                    
        if totalcnt <= (count + 25): break
        else: count = count + 25
    # Now we need to  a) delete the devices that do not have a post-staging template
    # b) deploy the device templates with the Controller info
    newdevice = []
    for dev in glbl.vnms.data['devices']:
      if "poststaging-template" not in dev or "deployed" not in dev:
         mlog.warn("Skipping Device={0} from the list because post-staging template was not found or device not in proper state".format(dev["name"]))
         glbl.vnms.data['devices'].remove(dev)

    # for each of the devices call the template workflow and the device workflow
    workflow_template_list = []
    for dev in glbl.vnms.data['devices']:
      if dev["poststaging-template"] not in workflow_template_list:
        if deploy_template_workflow(dev) :
          workflow_template_list.append(dev["poststaging-template"])
          deploy_device_workflow(dev)
      else:
        # the workflow template has already been deployed sucessfully
        deploy_device_workflow(dev)

    write_outfile(glbl.vnms,glbl.analy,glbl.cntlr,glbl.cust, glbl.admin)
    return ''
    

def get_wan_ntwk( _method, _uri, _payload,resp='200', _name=None,_ofile=None):
    global vnms, analy, cntlr, cust, mlog
    resp2 = '202'
    vdict = {}
    vdict = {'body': _payload, 'resp': resp, 'resp2': resp2, 'method': _method, 'uri': _uri}
    mlog.info("In function {0} with outfile={1}".format(get_wan_ntwk.__name__,_ofile))
    [out, resp_str] = common.call(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
    if out == 1 and len(resp_str) > 3:
      jstr = json_loads(resp_str)
      mywan = {}
      for i in jstr:
        if 'name' in i:
          mywan[i["name"]] =  i["transport-domains"][0]
        else:
          mlog.error("Could not get Wan Ntwk")

      glbl.vnms.data['wanNtwk'] =  {}
      glbl.vnms.data['wanNtwk'] =  mywan
        
      write_outfile(glbl.vnms,glbl.analy,glbl.cntlr,glbl.cust, glbl.admin)
    else: 
      mlog.error("Could not get Wan Ntwk")
    return ''

def get_parent_orgid( _method, _uri, _payload,resp='200',_name=None, _ofile=None):
    global vnms, analy, cntlr, cust, mlog
    resp2 = '202'
    vdict = {}
    vdict = {'body': _payload, 'resp': resp, 'resp2': resp2, 'method': _method, 'uri': _uri}
    mlog.info("In function {0} with outfile={1}".format(get_parent_orgid.__name__,_ofile))
    [out, resp_str] = common.call(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
    if out == 1 and len(resp_str) > 3:
      jstr = json_loads(resp_str)
      if 'uuid' in jstr:
        glbl.vnms.data['parentOrgId'] = ""
        glbl.vnms.data['parentOrgId'] = jstr['uuid']
        write_outfile(glbl.vnms,glbl.analy,glbl.cntlr,glbl.cust, glbl.admin)
      else:
        mlog.error("Could not get parent Org UUID")
    else: 
      mlog.error("Could not get parent Org UUID")
    return ''


def get_controller_workflow( _method, _uri, _payload,resp='200', _ofile=None):
    global vnms, analy, cntlr, cust, mlog
    resp2 = '202'
    vdict = {}
    vdict = {'body': _payload, 'resp': resp, 'resp2': resp2, 'method': _method, 'uri': _uri}
    mlog.info("In function {0} with outfile={1}".format(get_controller_workflow.__name__,_ofile))
    if _ofile is None: 
       mlog.error("No file provided .. exiting")
       sys.exit("No file provided .. exiting")
    [out, resp_str] = common.call(vdict,content_type='json',ncs_cmd="no")
    if out == 1 and len(resp_str) > 3:
      jstr = json_loads(resp_str)
      out = common.create_out_data("POST","200","/vnms/sdwan/workflow/controllers/controller", jstr)
      fp=open(_ofile,"w+")
      out1 = json.dumps(out, indent=4)
      fp.write(out1)
      fp.close()
    return ''

def delete_controller_workflow(_name ):
    resp2 = '202'
    vdict = {}
    _uri = '/vnms/sdwan/workflow/controllers/controller/' + _name
    _payload = {}
    #np = json_loads(a)
    mlog.info("In function {0} ".format(delete_controller_workflow.__name__))
    vdict = {'body': _payload , 'resp': '200', 'resp2': resp2, 'method': "DELETE", 'uri': _uri}
    [out, resp_str] = common.call(vdict,content_type='json',ncs_cmd="yes")
    if out == 1 and len(resp_str) > 3:
      jstr = json_loads(resp_str)
      pprint(jstr)
    return 

def delete_controller_by_uuid( _uuid ):
    resp2 = '202'
    vdict = {}
    _uri = '/api/config/nms/actions/_operations/delete-appliance'
    _payload = {}
    _payload = { "delete-appliance": {"applianceuuid": "%s" % str(_uuid),
                 "clean-config": "false", 
                 "reset-config": "false", 
                 "load-defaults": "false" }}
    a=json.dumps(_payload)
    #np = json_loads(a)
    mlog.info("In function {0} ".format(delete_controller_by_uuid.__name__))
    vdict = {'body': a, 'resp': '200', 'resp2': resp2, 'method': "POST", 'uri': _uri}
    [out, resp_str] = common.call(vdict,content_type='json',ncs_cmd="yes")
    if out == 1 and len(resp_str) > 3:
      jstr = json_loads(resp_str)
      #pprint(jstr)
    return 

def post_script():
    # we need to write a few files so it is easier on the next phase
    global vnms, analy, cntlr, cust, admin, mlog
    mlog.info("In function {0} ".format(post_script.__name__))
    '''
    i = 0
    for dev in glbl.cntlr.data['old_cntlr']:
      jstr = {}
      _uri = '/vnms/sdwan/workflow/controllers/controller/' + dev['name']
      out = common.create_out_data("GET","200",_uri, jstr)
      if i == 0: 
        fname = "in_phase3/" + "{:03d}_GET_CONTROLLER_WORKFLOW.json".format(i)
      else:
        fname = "in_phase3/" + "{:03d}_GET_PEER_CONTROLLER_WORKFLOW.json".format(i)
      fp=open(fname,"w+")
      out1 = json.dumps(out, indent=4)
      fp.write(out1)
      fp.close()
      i = i + 1
    '''

    _str = '/api/config/devices/template/'+ '{{templateName}}' 
    for i in range(13,17):
      jstr = {}
      if i == 13:
        _uri= _str + '/config/orgs/org/alpha/sd-wan/controllers/controller'
        fname = "in_phase3/" + "{:03d}_GET_SDWAN_CONTROLLER.json".format(i)
      elif i == 14:
        _uri= _str + '/config/system/sd-wan/controllers/controller?deep=true&offset=0&limit=25'
        fname = "in_phase3/" + "{:03d}_GET_SYSTEM_CONTROLLER.json".format(i)
      elif i == 15:
        _uri= _str + '/config/orgs/org-services/alpha/ipsec/vpn-profile?deep=true&offset=0&limit=25'
        fname = "in_phase3/" + "{:03d}_GET_IPSEC_VPN_PROFILE.json".format(i)
      elif i == 16:
        _uri= _str + '/config/system/vnf-manager'
        fname = "in_phase3/" + "{:03d}_GET_VNF_MANAGER.json".format(i)

      out = common.create_out_data("GET","200",_uri, jstr)
      fp=open(fname,"w+")
      out1 = json.dumps(out, indent=4)
      fp.write(out1)
      fp.close()


    _str = '/api/config/devices/device/'+ '{{deviceName}}' 
    for i in range(23,27):
      jstr = {}
      if i == 23:
        _uri= _str + '/config/orgs/org/alpha/sd-wan/controllers/controller?deep=true&offset=0&limit=25'
        fname = "in_phase3/" + "{:03d}_GET_DEVICE_SDWAN_CONTROLLER.json".format(i)
      elif i == 24:
        _uri= _str + '/config/system/sd-wan/controllers/controller?deep=true&offset=0&limit=25'
        fname = "in_phase3/" + "{:03d}_GET_DEVICE_SYSTEM_CONTROLLER.json".format(i)
      elif i == 25:
        _uri= _str + '/config/orgs/org-services/alpha/ipsec/vpn-profile?deep=true&offset=0&limit=25'
        fname = "in_phase3/" + "{:03d}_GET_DEVICE_IPSEC_VPN_PROFILE.json".format(i)
      elif i == 26:
        _uri= _str + '/config/system/vnf-manager'
        fname = "in_phase3/" + "{:03d}_GET_DEVICE_VNF_MANAGER.json".format(i)

      out = common.create_out_data("GET","200",_uri, jstr)
      fp=open(fname,"w+")
      out1 = json.dumps(out, indent=4)
      fp.write(out1)
      fp.close()
    return
        

def get_existing_controller():
    global vnms, analy, cntlr, cust, admin, mlog
    resp2 = '202'
    vdict = {}
    _payload = {}
    mlog.info("In function {0} ".format(get_existing_controller.__name__))
    vdict = {'body': _payload, 'resp': '200', 'resp2': resp2, 'method': "GET", 'uri':"/vnms/appliance/summary"}
    [out, resp_str] = common.call(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
    old_cntlr_list = []
    if out == 1 and len(resp_str) > 3:
      jstr = json_loads(resp_str)
      mlog.info("Device list = {0}".format(json.dumps(jstr,indent=4)))
      old_cntlr_list = list(filter(lambda x: x['type'] == 'controller', jstr))
      dev_list = list(filter(lambda x: x['type'] != 'controller', jstr))
      hub_cntlr_list = list(filter(lambda x: x['type'] == 'hub-controller', jstr))
      if len(hub_cntlr_list) > 0: 
        new_hub_cntlr_list = copy.deepcopy( hub_cntlr_list )
        glbl.vnms.data['hub_cntlr_present'] = 1
        glbl.vnms.data['hub_cntlr_devices'] = []
        glbl.vnms.data['hub_cntlr_devices'] = new_hub_cntlr_list
        mlog.warn("Hub Controller Num = {0} present".format(len(new_hub_cntlr_list)))
      else:
        glbl.vnms.data['hub_cntlr_present'] = 0

	 
      
      glbl.vnms.data['devices'] = []
      glbl.vnms.data['devices'] = dev_list
      write_outfile(glbl.vnms,glbl.analy,glbl.cntlr,glbl.cust, glbl.admin)
      #pprint(jstr)

      if len(old_cntlr_list) != 2:
        mlog.error("Number of Existing Controllers not 2.It is  = {0}".format(len(old_cntlr_list)))

      # Make sure the cntrollers are NOT the New controllers
      # this can happen if this file is executed more than once
      found = 0
      for dev in old_cntlr_list: 
        if ((dev["name"] == glbl.cntlr.data["new_cntlr"][0]["controllerName"]) or 
            (dev["name"] == glbl.cntlr.data["new_cntlr"][1]["controllerName"])): 
          found = found + 1
      if found > 1 :
        # We have already made the necessary check in the main function 
        # it must be in glbl.vnms.data["old_cntlr"]  or we fail
        if len(glbl.cntlr.data["old_cntlr"]) > 0:
          old_cntlr_list = glbl.cntlr.data["old_cntlr"]
        else:
          mlog.error("Can not find old controller data -- exiting")
          sys.exit("Can not find old controller data")
      else:
        pass
      for dev in old_cntlr_list: 
        # No need to do this step if we the earlier found was matched
        if found > 1: break 
        _payload = {}
        uri = "/vnms/sdwan/workflow/controllers/controller/" + dev["name"]
        vdict = {'body': _payload, 'resp': '200', 'resp2': resp2, 'method': "GET", 'uri':uri }
        [out, resp_str] = common.call(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
        if len(resp_str) > 3 :
          jstr = json_loads(resp_str)
          if "versanms.sdwan-controller-workflow" in jstr and "peerControllers" in jstr["versanms.sdwan-controller-workflow"]:
            dev["peerControllers"]=  []
            dev["peerControllers"]=  jstr["versanms.sdwan-controller-workflow"]["peerControllers"]

        if not controller_connect(dev):
          # We can connect from the New Director to the OLD Controller. This is a NO NO
          mlog.error("The NEW Director is able to communicate with the OLD Controllers. Please follow instructions. ")
          sys.exit("The NEW Director is able to communicate with the OLD Controllers. Please follow instructions. ")

      #glbl.cntlr.data['old_cntlr'] = []
      for dev in old_cntlr_list: 
        if found > 1: break 
        if  dev['type'] == 'controller': 
          if ( dev['name'] == glbl.cntlr.data['new_cntlr'][0]["controllerName"] 
               or dev['name'] == glbl.cntlr.data['new_cntlr'][1]["controllerName"] ):
            continue
          else:
            mlog.warn("Deleting OLD Controller {0} from NEW Director and checking status. Please be patient".format(dev["name"]))
            delete_controller_by_uuid( dev['uuid'])
            time.sleep(20)
            for i in range(0,5):
              [status,resp_str] = common.check_controller_status(name=dev['name'],resp='404')
              if status == 1: 
                mlog.warn("OLD Controller {0} successfully deleted for NEW Director. Any previous errors can be ignored".format(dev["name"]))
                break
              else : time.sleep(2)

            mlog.warn("Deleting OLD Controller {0} Workflow".format(dev["name"]))
            delete_controller_workflow(dev['name'])
            if len(glbl.cntlr.data['old_cntlr']) == 0:
              glbl.cntlr.data['old_cntlr'].append(dev) 
            else:
              #Make sure we are not rewriting the same data again and again
              found = 0
              for i in range(len(glbl.cntlr.data['old_cntlr'])):
                if dev['name'] == glbl.cntlr.data['old_cntlr'][i]['name']: found = 1
              if found == 0:
                glbl.cntlr.data['old_cntlr'].append(dev) 

      write_outfile(glbl.vnms,glbl.analy,glbl.cntlr,glbl.cust, glbl.admin)
      return True
    else:
      mlog.error("Did not find devices = {0}".format(json.dumps(jstr,indent=4)))

    return False

def create_dns_config( _method, _uri,_payload,resp='200'):
    vdict = {}
    vdict = {'body': _payload, 'resp': resp, 'method': _method, 'uri': _uri}
    [out, resp_str] = common.call(vdict,content_type='json',ncs_cmd="no")
    if out == 1 and len(resp_str) > 3:
      jstr = json_loads(resp_str)
      mlog.info("Response for Method={0} URI={1} str = {2}".format(_method,_uri,json.dumps(jstr,indent=4)))
    return ''

def yes_or_no3(question, option = 0):
    if pyVer.major== 3:
      reply = str(input(question+' (y/n): ')).lower().strip()
    else:
      reply = str(raw_input(question+' (y/n): ')).lower().strip()
    if option == 0:
      if reply[0] == 'n': return 1
      elif reply[0] == 'y': return 1
    return 1

def yes_or_no2(question):
    if pyVer.major == 3:
      reply = str(input(question+' (y/n): ')).lower().strip()
    else: 
      reply = str(raw_input(question+' (y/n): ')).lower().strip()
    if reply[0] == 'n': return 0
    elif reply[0] == 'y': return 1
    else:
        return yes_or_no2("Did not understand input: Please re-enter ") 

def yes_or_no(question):
    if pyVer.major == 3:
      reply = str(input(question+' (y[default]/n/s): ')).lower().strip()
    else:
      reply = str(raw_input(question+' (y[default]/n/s): ')).lower().strip()
    if reply[0] == 'n': return 0
    elif reply[0] == 'y': return 1
    elif reply[0] == 's': return 2
    else:
        return yes_or_no("Did not understand input: Please re-enter ") 

def write_outfile(_vnms,_analy,_cntlr,_cust, _admin):
    global vnms, analy, cntlr, cust, admin, mlog
    mlog.info("In function {0} : Output file:vm_phase3.json".format(write_outfile.__name__))
    jstr = {}
    jstr["Vnms"] = _vnms.data
    jstr["Analytics"] = _analy.data
    jstr["Controller"] = _cntlr.data
    jstr["Admin"] = _admin.data
    jstr["Customer"] = _cust.data
    fin=open("vm_phase3.json", "w+")
    mstr1 = json.dumps(jstr, indent=4)
    fin.write(mstr1)
    fin.close()

def read_input_file(_infile, option=None):
    global vnms, analy, cntlr, cust, admin, auth, debug, mlog, mdict

    fp = open(_infile,"r")
    jstr = fp.read()
    fp.close()
    if option is None:
      mdict=json_loads(jstr)
      for _keys,_val in mdict.items():
        if _keys.lower() == "vnms": 
           vnms =  Vnms(_val)
        elif _keys.lower() == "analytics": 
           analy = Analytics(_val)
        elif _keys.lower() == "controller": 
           cntlr =  Controller(_val)
        elif _keys.lower() == "customer": 
           cust = Customer(_val)
           #pprint(cust.data)
        elif _keys.lower() == "admin": 
           admin = Admin(_val)
      return
    else:
      return json_loads(jstr)


def process_normal(fil,template_env,template_path, option=False):
    global vnms, analy, cntlr, cust, admin, auth, debug, mlog


    dir_items = sorted(os.listdir(template_path))
    for i in dir_items:
       # check the format of the files
       if not re.match(r'^\d{3}_.+\.json$', i):
          continue
       if option: 
          # Here we are dealing with the re-read case. We just need to read one file 
          if not re.match(r'^\d{3}_GET_DEVICE_GROUP\.json$', i):
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
       my_template = template_env.get_template(i)
       _newkey = _key.split(".")[0]
       #print("==============In %s==========" %(_newkey))
       mlog.warn("==============In {0}==========".format(_newkey))
       #ret = yes_or_no("Continue: " )
       #if ret == 0 : exit(0)
       #elif ret == 2: continue
       if _key[0:3] == 'GET':
         if _newkey == 'GET_RELEASE_INFO':
           x= my_template.render()
           y= json_loads(x)
           _val(str(y['method']), str(y['path']), json.dumps(y['payload']),resp=str(y['response']),_name=None,_ofile=None)
         elif _newkey == 'GET_DEVICE_GROUP':
           x= my_template.render()
           y= json_loads(x)
           _val(str(y['method']), str(y['path']), json.dumps(y['payload']),resp=str(y['response']),_name=None,_ofile=None)
         elif _newkey == 'GET_PARENT_ORGID':
           x= my_template.render()
           y= json_loads(x)
           _val(str(y['method']), str(y['path']), json.dumps(y['payload']),resp=str(y['response']),_name=None,_ofile=None)
         elif _newkey == 'GET_WAN_NETWORK':
           x= my_template.render(parentOrgUUID=glbl.vnms.data['parentOrgId'])
           y= json_loads(x)
           _val(str(y['method']), str(y['path']), json.dumps(y['payload']),resp=str(y['response']),_name=None,_ofile=None)
       elif _newkey == 'CREATE_TIME_ZONE':
         x= my_template.render()
         y= json_loads(x)
         _val(str(y['method']), str(y['path']), json.dumps(y['payload']),resp=str(y['response']))
       elif _newkey == 'CREATE_NTP_SERVER':
         x= my_template.render()
         y= json_loads(x)
         _val(str(y['method']), str(y['path']), json.dumps(y['payload']),resp=str(y['response']))
       elif _newkey == 'CREATE_DNS_SERVER':
         x= my_template.render()
         y= json_loads(x)
         _val(str(y['method']), str(y['path']), json.dumps(y['payload']),resp=str(y['response']))
       elif _newkey == 'SET_NMS_PROVIDER':
         x= my_template.render()
         y= json_loads(x)
         _val(str(y['method']), str(y['path']), json.dumps(y['payload']),resp=str(y['response']))
       elif _newkey == 'CREATE_ANALYTICS_CLUSTER':
         x= my_template.render()
         y= json_loads(x)
         _val(str(y['method']), str(y['path']), json.dumps(y['payload']),resp=str(y['response']))
       elif _newkey == 'CREATE_AUTH_CONNECTOR':
         x= my_template.render()
         y= json_loads(x)
         _val(str(y['method']), str(y['path']), json.dumps(y['payload']),resp=str(y['response']))
       elif _newkey == 'CREATE_DEFAULT_AUTH_CONNECTOR' or _newkey == 'DELETE_AUTH_CONNECTOR':
         x= my_template.render()
         y= json_loads(x)
         _val(str(y['method']), str(y['path']), json.dumps(y['payload']),resp=str(y['response']))
       elif _newkey == 'CREATE_CONTROLLER' or _newkey == 'CREATE_PEER_CONTROLLER':
         if _newkey == 'CREATE_CONTROLLER': 
           # before we get into this we need to Delete the existing controllers and 
           # the function get_existing_controller will delete both the controllers and
           # we need to do this once
           rv = get_existing_controller()
           if not rv:
             mlog.error("Can not find appliance data .. exiting")
             sys.exit("Can not find appliance data .. exiting")
         x= my_template.render( )
         y= json_loads(x)
         _name=str(y['payload']['versanms.sdwan-controller-workflow']['controllerName'])
         _val(str(y['method']), str(y['path']), json.dumps(y['payload']),resp=str(y['response']),name=_name)
       elif _newkey == 'DEPLOY_CONTROLLER_WORKFLOW' or _newkey == 'DEPLOY_PEER_CONTROLLER_WORKFLOW':
         x= my_template.render( )
         y= json_loads(x)
         a=str(y['path']).rsplit("/",1)[-1]
         _val(str(y['method']), str(y['path']), json.dumps(y['payload']),resp=str(y['response']),name=a)
       elif _newkey == 'ORG_DEPLOY_WORKFLOW':
         x= my_template.render( )
         y= json_loads(x)
         a=str(y['path']).rsplit("/",1)[-1]
         _val(str(y['method']), str(y['path']), json.dumps(y['payload']),resp=str(y['response']),name=a)
       elif _newkey == 'SET_CONTROLLER_CONFIG_BUILD' or _newkey == 'SET_PEER_CONTROLLER_CONFIG_BUILD':
         x= my_template.render( )
         y= json_loads(x)
         a=str(y['path']).rsplit("/")[-3]
         _val(str(y['method']), str(y['path']), json.dumps(y['payload']),resp=str(y['response']),name=a)
       elif (_newkey == 'SET_CONTROLLER_VNI' or
             _newkey == 'SET_CONTROLLER_ROUTING' or
             _newkey == 'SET_CONTROLLER_NTP' or
             _newkey == 'SET_CONTROLLER_OAM_ALARMS' or
             _newkey == 'SET_CONTROLLER_ORG_SERVICES' or
             _newkey == 'SET_CONTROLLER_ORG' or
             _newkey == 'SET_CONTROLLER_SYSTEM' or
             _newkey == 'SET_CONTROLLER_COMMIT' or
             _newkey == 'SET_CONTROLLER_SYNCH'): 
         x= my_template.render( )
         y= json_loads(x)
         _val(str(y['method']), str(y['path']), json.dumps(y['payload']),resp=str(y['response']))
       elif (_newkey == 'SET_PEER_CONTROLLER_VNI' or 
             _newkey == 'SET_PEER_CONTROLLER_ROUTING' or 
             _newkey == 'SET_PEER_CONTROLLER_NTP' or 
             _newkey == 'SET_PEER_CONTROLLER_OAM_ALARMS' or 
             _newkey == 'SET_PEER_CONTROLLER_ORG_SERVICES' or 
             _newkey == 'SET_PEER_CONTROLLER_ORG' or 
             _newkey == 'SET_PEER_CONTROLLER_SYSTEM' or 
             _newkey == 'SET_PEER_CONTROLLER_COMMIT' or 
             _newkey == 'SET_PEER_CONTROLLER_SYNCH'):
         x= my_template.render( )
         y= json_loads(x)
         _val(str(y['method']), str(y['path']), json.dumps(y['payload']),resp=str(y['response']))


def my_split_string(_str, n):
    my_list = [_str[index : index + n] for index in range(0, len(_str), n)]
    return my_list


def get_terminal_size():
  global MYLINES, MYCOL
  os_env = os.environ

  if "LINES" in os_env:
    MYLINES = int(os_env["LINES"]) - 5
  else:
    MYLINES = 20
  if "COLUMNS" in os_env:
    MYCOL = (int(os_env["COLUMNS"])/10 - 1)*10
  else:
    MYCOL = 70


def show_devices_status( ):
    global vnms, analy, cntlr, cust, admin, auth, debug, mlog, NOT_DEPLOYED 
    cnt_list = []
    count = 1
    pcol1=0
    pcol2=0
    pcol3=0
    '''
    for i in range(len(glbl.vnms.data['devices'])):
      #if len(glbl.vnms.data["devices"][i]["name"]) > pcol1 : pcol1= len(glbl.vnms.data["devices"][i]["name"]) + 1 
      #if len(glbl.vnms.data["devices"][i]['poststaging-template']) > pcol2 : pcol2= len(glbl.vnms.data["devices"][i]['poststaging-template']) + 1
      #if len(glbl.vnms.data["devices"][i]['dg-group']) > pcol3 : pcol3= len(glbl.vnms.data["devices"][i]['dg-group']) + 1 
      cnt_list.append(count)
      count = count + 1
    '''
    cnt_list = list(range(1,len(glbl.vnms.data['devices'])+1))
    comb_dict=dict(zip(cnt_list,glbl.vnms.data['devices']))
    pcol1=int(MYCOL/4)
    pcol2=int(MYCOL/4)
    pcol3=int(MYCOL/4)

    print ("The following in the status of devices from Director = {0}".format( glbl.admin.data['new_dir']['vd_ip']))

    # Header
    print("-" * int(4+pcol1+pcol2+pcol3+15+6))
    print("|{0:<{col0}}|{1:<{col1}}|{2:<{col2}}|{3:<{col3}}|{4:<{col4}}|".format("Idx","Name","P-STemplate","DG-Group","Status",
                                              col0=4,col1=pcol1,col2=pcol2,col3=pcol3,col4=15))
    print("-" * int(4+pcol1+pcol2+pcol3+15+6))
    cnt = 0
    # We want 20 lines of output. We can try and read it from os.environ. Right now just hard-coding
    out_line = 20
    new_out_line = out_line

    for _key,v in comb_dict.items():
      cnt = cnt + 1
      namelist = []
      post_staginglist = []
      dg_grouplist = []
      #if len(v['name']) > pcol1:
      namelist = my_split_string(v['name'], pcol1)
      #if len(v['poststaging-template']) > pcol2: 
      post_staginglist = my_split_string(v['poststaging-template'], pcol2)
      #if len(v['dg-group']) > pcol3:
      dg_grouplist = my_split_string(v['poststaging-template'], pcol3)
      # find the max of 3 values to determine how many lines we need to add. If the max is 1 we do not need to add any lines
      mymax = max( len(namelist), len(post_staginglist), len(dg_grouplist))
      #cnt = cnt + mymax
      if mymax != 1 :
        new_out_line = new_out_line - mymax + 1

      if "deployed" in v and v["deployed"] == "1":
        if mymax == 1:
          print("|{0:<{col0}}|{1:<{col1}}|{2:<{col2}}|{3:<{col3}}|{green}{4:<{col4}}{endc}|".format(_key,v['name'],v['poststaging-template'],
                      v['dg-group'],"OK",green=bcolors.OKGREEN,endc=bcolors.ENDC,
                      col0=4,col1=pcol1,col2=pcol2,col3=pcol3,col4=15))
        else:
          for i in range(mymax):
            _namelist = "" if i >= len(namelist) else namelist[i]
            _post_staginglist = "" if i >= len(post_staginglist) else post_staginglist[i]
            _dg_grouplist = "" if i >= len(dg_grouplist) else dg_grouplist[i]
            _nd_status = "OK"  if i == 0 else ""
            _keyl = "" if i > 0 else _key

            print("|{0:<{col0}}|{1:<{col1}}|{2:<{col2}}|{3:<{col3}}|{green}{4:<{col4}}{endc}|".
                  format(_keyl,_namelist,_post_staginglist,
                  _dg_grouplist,_nd_status, green=bcolors.OKGREEN,endc=bcolors.ENDC,
                  col0=4,col1=pcol1,col2=pcol2,col3=pcol3,col4=15))

      else : 
        NOT_DEPLOYED = 1
        if mymax == 1:
          print("|{0:<{col0}}|{1:<{col1}}|{2:<{col2}}|{3:<{col3}}|{warn}{4:<{col4}}{endc}|".format(_key,v['name'],v['poststaging-template'],
                      v['dg-group'],"NOT OK",warn=bcolors.OKWARN,endc=bcolors.ENDC,
                      col0=4,col1=pcol1,col2=pcol2,col3=pcol3,col4=15))
        else:
          for i in range(mymax):
            _namelist = "" if i >= len(namelist) else namelist[i]
            _post_staginglist = "" if i >= len(post_staginglist) else post_staginglist[i]
            _dg_grouplist = "" if i >= len(dg_grouplist) else dg_grouplist[i]
            _nd_status = "NOT OK"  if i == 0 else ""
            _keyl = "" if i > 0 else _key

            print("|{0:<{col0}}|{1:<{col1}}|{2:<{col2}}|{3:<{col3}}|{warn}{4:<{col4}}{endc}|".
                  format(_keyl,_namelist,_post_staginglist,
                  _dg_grouplist,_nd_status, warn=bcolors.OKWARN,endc=bcolors.ENDC,
                  col0=4,col1=pcol1,col2=pcol2,col3=pcol3,col4=15))
      if  cnt%new_out_line == 0 and _key !=  len(comb_dict) :
        #print(new_out_line)
        print("-" * int(4+pcol1+pcol2+pcol3+15+6))
        yes_or_no3("Press any key to continue",1 )
        print("-" * int(4+pcol1+pcol2+pcol3+15+6))
        print("|{0:<{col0}}|{1:<{col1}}|{2:<{col2}}|{3:<{col3}}|{4:<{col4}}|".format("Idx","Name","P-STemplate","DG-Group","Status",
                                              col0=4,col1=pcol1,col2=pcol2,col3=pcol3,col4=15))
        print("-" * int(4+pcol1+pcol2+pcol3+15+6))
        #Now reset things back
        new_out_line = out_line 
        cnt = 0

    print("-" * int(4+pcol1+pcol2+pcol3+15+6))
    print(bcolors.ENDC)
    if NOT_DEPLOYED == 1:
      mlog.warn (bcolors.OKWARN + "If any of the Templates or Devices are in error, the table above will show as NOT OK.\n" + 
           " You must fix all the errors on the Director and then YOU MUST re-run the program as: \n" +
           "          ./VMMigr_phase2.py -f vm_phase3.json -r                    \n" + 
           "NOTE: The input file MUST be vm_phase3.json and the -r option MUST be provided.\n"+ 
           "You can re-run the program  multiple time using the same command.\n" +
           "IF THE ERRORS ARE NOT FIXED, the corresponding devices will NOT be migrated." + bcolors.ENDC)


def main():
    #global vnms, analy, cntlr, cust, admin, auth, debug, mlog, mdict
    global mlog, mdict
    #mdict = readfile("in_rest.cfg")
    argcheck()
    debug = int(args['debug'])
    infile = args['file']
    reread=args['read']
    LOG_FILENAME = 'vmMigrate.log'
    LOG_SIZE = 8 * 1024 * 1024
    if reread and infile.find("vm_phase3.json") == -1:
      print("If you are using re-read option the file MUST be vm_phase3.json")
      usage()
      sys.exit(0)
    mlog,f_hndlr,s_hndlr=glbl.init(infile,LOG_FILENAME, LOG_SIZE,"VMMigr2",debug)
    if debug == 0:
      glbl.setup_level(f_hndlr, logging.INFO) # Setting fileHandler loglevel
      glbl.setup_level(s_hndlr, logging.WARNING) # Setting stream Handler loglevel
    else:
      glbl.setup_level(f_hndlr, logging.INFO)
      glbl.setup_level(s_hndlr, logging.INFO)
    mlog.warn(bcolors.OKWARN + "===============Starting Phase 2 Execution==========" + bcolors.ENDC)
    if not reread: 
      mlog.warn(bcolors.OKWARN + "Before we proceed below are a few directions:\n" + 
                              "Have you restored the Director using the backup\n" + 
                              "Have you run the vnms-startup.sh script\n" + 
                              "Have you disabled and re-enabled HA\n" + 
                              "Have you ensured that communication from NEW Director to OLD Controller is not possible\n" + 
                              "Did you check the passswords in the input file allow UI access\n" + bcolors.ENDC)
    ret = yes_or_no2("To continue press y and to exit press n : " )
    if ret == 0 : return
    elif ret == 2: pass
    if debug == 0:
        mlog.setLevel(logging.WARNING)

    # before we write the output file we need to see if old_cntlr data is present or not
    # Initialize it
    glbl.cntlr.data["old_cntlr"] = []
    if not reread and os.path.exists("vm_phase3.json"):
      newvdict = read_input_file("vm_phase3.json",1)
      if ('Controller' in newvdict and 'old_cntlr' in newvdict['Controller'] and 
        len(newvdict['Controller']['old_cntlr']) > 0 ):
        # we found the data -- now we can replace the controller list
        glbl.cntlr.data["old_cntlr"] = newvdict['Controller']['old_cntlr']

    write_outfile(glbl.vnms,glbl.analy,glbl.cntlr,glbl.cust, glbl.admin)
    get_terminal_size()



    fil = OrderedDict()
    #############################NEW###########################
    fil['GET_RELEASE_INFO.json'] = get_dir_release_info
    fil['CREATE_TIME_ZONE.json'] = get_dir_time_zones 
    fil['CREATE_NTP_SERVER.json'] =  get_dir_ntp_server 
    fil['CREATE_DNS_SERVER.json'] = get_dir_dns_server
    fil['SET_NMS_PROVIDER.json'] = set_nms_provider
    fil['GET_PARENT_ORGID.json'] = get_parent_orgid
    fil['GET_WAN_NETWORK.json'] = get_wan_ntwk

    #fil['CREATE_ANALYTICS_CLUSTER.json'] = get_dir_analytics_cluster
    #fil['DELETE_AUTH_CONNECTOR.json'] = get_dir_auth_connector_config
    #fil['CREATE_AUTH_CONNECTOR.json'] = get_dir_auth_connector_config
    #fil['CREATE_DEFAULT_AUTH_CONNECTOR.json'] = get_dir_default_auth_connector
    #fil['CREATE_AUTH_CONNECTOR_CONFIG.json'] = get_dir_auth_connector_config

    fil['CREATE_CONTROLLER.json'] = create_controller
    fil['DEPLOY_CONTROLLER_WORKFLOW.json'] = deploy_controller
    fil['CREATE_PEER_CONTROLLER.json'] = create_controller
    fil['DEPLOY_PEER_CONTROLLER_WORKFLOW.json'] = deploy_controller
    fil['ORG_DEPLOY_WORKFLOW.json'] = deploy_org_workflow

    fil['SET_CONTROLLER_CONFIG_BUILD.json'] = create_controller_build
    fil['SET_CONTROLLER_VNI.json'] = create_dns_config
    fil['SET_CONTROLLER_ROUTING.json'] = create_dns_config
    fil['SET_CONTROLLER_NTP.json'] = create_dns_config
    fil['SET_CONTROLLER_OAM_ALARMS.json'] = create_dns_config
    fil['SET_CONTROLLER_ORG_SERVICES.json'] = create_dns_config
    fil['SET_CONTROLLER_ORG.json'] = create_dns_config
    fil['SET_CONTROLLER_SYSTEM.json'] = create_dns_config
    fil['SET_CONTROLLER_COMMIT.json'] = create_dns_config
    fil['SET_CONTROLLER_SYNCH.json'] = create_dns_config

    fil['SET_PEER_CONTROLLER_CONFIG_BUILD.json'] = create_controller_build
    fil['SET_PEER_CONTROLLER_VNI.json'] = create_dns_config
    fil['SET_PEER_CONTROLLER_ROUTING.json'] = create_dns_config
    fil['SET_PEER_CONTROLLER_NTP.json'] = create_dns_config
    fil['SET_PEER_CONTROLLER_OAM_ALARMS.json'] = create_dns_config
    fil['SET_PEER_CONTROLLER_ORG_SERVICES.json'] = create_dns_config
    fil['SET_PEER_CONTROLLER_ORG.json'] = create_dns_config
    fil['SET_PEER_CONTROLLER_SYSTEM.json'] = create_dns_config
    fil['SET_PEER_CONTROLLER_COMMIT.json'] = create_dns_config
    fil['SET_PEER_CONTROLLER_SYNCH.json'] = create_dns_config
    if not reread:
      fil['GET_DEVICE_GROUP.json'] = get_device_group
    else: 
      fil['GET_DEVICE_GROUP.json'] = get_device_group_new

    template_path = os.path.abspath(sys.argv[0]).rsplit("/",1)[0] + "/" + "in_phase2"
    if not os.path.exists( template_path ):
      sys.exit("Directory: {0} does not exists".format(template_path)) 
    tmp_outpath = os.path.abspath(sys.argv[0]).rsplit("/",1)[0] + "/" + "in_phase3"
    if not os.path.exists( tmp_outpath ):
      os.makedirs(tmp_outpath )

    template_loader = jinja2.FileSystemLoader(searchpath=template_path)
    template_env = jinja2.Environment(loader=template_loader,undefined=jinja2.StrictUndefined)
    template_env.filters['jsonify'] = json.dumps

    process_normal(fil,template_env,template_path,reread)

    if not reread : post_script()
    show_devices_status( )
    if NOT_DEPLOYED == 0:
      mlog.warn(bcolors.OKWARN + "==============Completed ==========" + bcolors.ENDC)
      mlog.warn(bcolors.OKWARN + "Verify that the OLD Dir is accessible and proceed to run the next script.\n" + bcolors.ENDC)


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
      fp=open("vmphase2.err","w+")
      fp.write(_errlog)
      fp.close()
      if mlog:
        mlog.warn(bcolors.OKWARN + "Error log vmphase2.err is created since there were errors." + bcolors.ENDC)


