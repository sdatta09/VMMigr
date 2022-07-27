#!/usr/bin/env python2

import os, sys, signal, argparse
import jinja2
from jinja2.utils import concat
import re
import httplib
import requests
import time
import base64
import xmltodict
import subprocess
import json
from pprint import pprint
from collections import OrderedDict
#import uuid
from pprint import pprint
import logging
import logging.handlers
import glbl
import common 


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
  """ Add and check arguments for the script
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
    sys.exit("Exiting")

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


def get_default( _method, _uri,_payload,resp='200', ofile=None):
    global vnms, analy, cntlr, cust, mlog
    vdict = {}
    mlog.info("In function " + get_default.__name__)
    vdict = {'body': _payload, 'resp': resp, 'method': _method, 'uri': _uri}
    [out, resp_str] = common.newcall(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
    jstr = json.loads(resp_str)
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


def get_old_peer_controller_name(_cntlrdata):
    for _cntlr in glbl.cntlr.data['old_cntlr']:
      if _cntlrdata == 2 and "peerControllers" in _cntlr :
        return _cntlr
      elif _cntlrdata == 1 and "peerControllers" not in _cntlr :
        return _cntlr



def get_new_peer_controller_name(_cntlrdata):
    for _cntlr in glbl.cntlr.data['new_cntlr']:
      if _cntlrdata == 2 and "peerControllers" in _cntlr :
        return _cntlr
      elif _cntlrdata == 1 and "peerControllers" not in _cntlr :
        return _cntlr

def get_n_fill_bind_data(_method, _uri, _payload,resp='200',vd_data=None, device=None):
    global vnms, analy, cntlr, cust, mlog

    if device is None or vd_data is None :
      mlog.error("Bad inputs in function {0} ".format(get_n_fill_bind_data.__name__))
      return
    
    mlog.info("In function {0} with device = {1} ".format(get_n_fill_bind_data.__name__, device["name"]))
    dg_group = device["dg-group"]
    devlist = filter(lambda x: x['dg-group'] == dg_group, glbl.vnms.data["devices"])
    uri = ("/nextgen/binddata/templateData/template/" + device["poststaging-template"] + 
          "/devicegroup/" + dg_group + "?offset=0&limit=25")
    payload = {}
    resp2 = '202'
    vdict = {}
    vdict = {'body': payload, 'resp': resp, 'resp2': resp2, 'method': "GET", 'uri': uri,
              'vd_ip' :  vd_data['vd_ip'], 'vd_rest_port': vd_data['vd_rest_port'],
               'auth': vd_data['auth']
    }
    [out, resp_str] = common.newcall(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
    if len(resp_str) > 3:
      jstr = json.loads(resp_str)
      mlog.info("Bind Data = {0}".format(json.dumps(jstr,indent=4)))
      old_p_cntlr = get_old_peer_controller_name(2)
      new_p_cntlr = get_new_peer_controller_name(2)
      found = 0
      if "deviceTemplateVariable" in jstr:
        for j in jstr["deviceTemplateVariable"]:  
          dev = None
          for i in devlist:
            if j["device"] == i["name"]:
              dev = i
              break
          if dev is None: 
            mlog.error ("Could not find device = {0}".format(j["device"]))
            continue
            
          if "variableBinding" in j and "attrs" in j["variableBinding"]:
            for var in j["variableBinding"]["attrs"] :
              if (var["name"] == '{$v_' + cust.data["custName"] + "_" + new_p_cntlr["controllerName"]
                             + '-Profile_Local_auth_email_identifier__IKELIdentifier}'):
                  var["value"]  = dev["local_auth_identity"]
                  found = found + 1
              elif (var["name"] == '{$v_' + cust.data["custName"] + "_" + new_p_cntlr["controllerName"]
                                    + '-Profile_Local_auth_email_key__IKELKey}'):
                  var["value"]  = dev["local_auth_key"]
                  found = found + 1
      if found >= 2 : 
        payload = json.dumps(jstr)
        vdict = {}
        uri = ("/nextgen/binddata/templateData/template/" + device["poststaging-template"] + 
              "/devicegroup/" + dg_group)
        vdict = {'body': payload, 'resp': resp, 'resp2': resp2, 'method': 'PUT', 'uri': uri,
              'vd_ip' :  vd_data['vd_ip'], 'vd_rest_port': vd_data['vd_rest_port'],
               'auth': vd_data['auth']
        }

        mlog.info("Sending PUT from function {0}".format(get_n_fill_bind_data.__name__))
        [out, resp_str] = common.newcall(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
        if len(resp_str) > 3:
          jstr = json.loads(resp_str)
          mlog.info("Bind data after PUT = {0}".format(json.dumps(jstr,indent=4)))
      for i in devlist:
        for j in glbl.vnms.data["devices"]:
          if i["name"] == j["name"] :
            j["status"] = ""
            j["status"] = "Complete"
      write_outfile(glbl.vnms,glbl.analy,glbl.cntlr,glbl.cust, glbl.admin)
              

    

def get_device_ipsec_vpn_profile( _method, _uri, _payload,resp='200',vd_data=None, device=None,_cntlr=2):
    global vnms, analy, cntlr, cust, mlog

    if device is None or vd_data is None :
      mlog.error("Bad inputs in function {0} ".format(get_device_ipsec_vpn_profile.__name__))
      return

    mlog.warn("Modifying IPSEC VPN Profile details for device = {0} ".format(device["name"]))
    resp2 = '202'
    vdict = {}
    vdict = {'body': _payload, 'resp': resp, 'resp2': resp2, 'method': _method, 'uri': _uri,
              'vd_ip' :  vd_data['vd_ip'], 'vd_rest_port': vd_data['vd_rest_port'],
               'auth': vd_data['auth']
    }
    [out, resp_str] = common.newcall(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
    if len(resp_str) > 3:
      jstr = json.loads(resp_str)
      newjstr = json.loads(resp_str)
      #mlog.info("IPSEC VPN Profile = {0}".format(json.dumps(jstr,indent=4)))
      scrub_list = [ "operations"]
      for i in scrub_list:
        common.scrub(jstr,i)

      old_p_cntlr = get_old_peer_controller_name(_cntlr)
      new_p_cntlr = get_new_peer_controller_name(_cntlr)
      # Delete the OlD VPN profile first
      payload = {}
      vdict = {}
      uri =  _uri.rsplit('?',1)[0]
      uri =  uri + "/" + old_p_cntlr["name"] + "-Profile"
      vdict = {'body': payload, 'resp': resp, 'resp2': resp2, 'method': 'DELETE', 'uri': uri,
                  'vd_ip' :  vd_data['vd_ip'], 'vd_rest_port': vd_data['vd_rest_port'],
                   'auth': vd_data['auth']
      }
      mlog.info("Sending DELETE from function {0}".format(get_device_ipsec_vpn_profile.__name__))
      [out, resp_str] = common.newcall(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
      # END OF DELETE    
      found = 0
      if "vpn-profile" in jstr: 
        for vpn in jstr["vpn-profile"] :
          #if vpn["name"] == (old_p_cntlr["name"] + "-Profile"):
          if vpn["name"].find(old_p_cntlr["name"]) != -1:
            vpn['name'] = new_p_cntlr["controllerName"] + "-Profile"
            if "local-auth-info" in vpn:
              # Key
              a = vpn["local-auth-info"]['key']
              if a.find("$v_") != -1:
                a=re.sub(old_p_cntlr["name"], new_p_cntlr["controllerName"], a, count=0,flags=0)
                vpn["local-auth-info"]['key'] = a
              else:
                if _cntlr == 2: 
                  vpn["local-auth-info"]['key'] = device["local_auth_key"]
                else:
                  vpn["local-auth-info"]['key'] = device["local1_auth_key"]
              # Email identifier
              b = vpn["local-auth-info"]['id-string']
              if b.find("$v_") != -1:
                b=re.sub(old_p_cntlr["name"], new_p_cntlr["controllerName"], b, count=0,flags=0)
                vpn["local-auth-info"]['id-string'] = b
              else:
                if _cntlr == 2: 
                  vpn["local-auth-info"]['id-string'] = device["local_auth_identity"]
                else:
                  vpn["local-auth-info"]['id-string'] = device["local1_auth_identity"]
              #vpn["local-auth-info"]['key'] = device["local_auth_key"]
              #vpn["local-auth-info"]['id-string'] = device["local_auth_identity"]
              #vpn["local-auth-info"]['key'] = a
              #vpn["local-auth-info"]['id-string'] = b
              found = found + 1
            if "peer-auth-info" in vpn:
              if _cntlr == 2: 
                vpn["peer-auth-info"]["id-string"] = device["remote_auth_identity"]
              else:
                vpn["peer-auth-info"]["id-string"] = device["remote1_auth_identity"]
              found = found + 1
            if found == 2: break
          #else:
          #  # New addition
          #  jstr["vpn-profile"].remove(vpn)

        # Only send the PATCH if we found all our elements
        if found == 2:
          #mlog.info("IPSEC VPN Profile after Deletion = {0}".format(json.dumps(jstr,indent=4)))
          payload = json.dumps(jstr)
          vdict = {}
          uri =  _uri.rsplit('?',1)[0]
          #uri = uri + "?unhide=deprecated"
          vdict = {'body': payload, 'resp': resp, 'resp2': resp2, 'method': 'PATCH', 'uri': uri,
                'vd_ip' :  vd_data['vd_ip'], 'vd_rest_port': vd_data['vd_rest_port'],
                 'auth': vd_data['auth']
          }
          mlog.info("Sending PATCH from function {0}".format(get_device_ipsec_vpn_profile.__name__))
          [out, resp_str] = common.newcall(vdict,content_type='json',ncs_cmd="no",jsonflag=1)

          if len(resp_str) > 3:
            jstr = json.loads(resp_str)
            mlog.info("IPSEC VPN Profile after PATCH = {0}".format(json.dumps(jstr,indent=4)))

        else:
          mlog.error("Not Sending PATCH from function {0}".format(get_ipsec_vpn_profile.__name__))
    else : 
      mlog.error("Not Sending PATCH from function {0}".format(get_ipsec_vpn_profile.__name__))
    return ''

def get_ipsec_vpn_profile( _method, _uri, _payload,resp='200',vd_data=None, device=None):
    global vnms, analy, cntlr, cust, mlog

    if device is None or vd_data is None :
      mlog.error("Bad inputs in function {0} ".format(get_ipsec_vpn_profile.__name__))
      return

    mlog.info("In function {0} with device = {1} ".format(get_ipsec_vpn_profile.__name__, device["name"]))
    resp2 = '202'
    vdict = {}
    vdict = {'body': _payload, 'resp': resp, 'resp2': resp2, 'method': _method, 'uri': _uri,
              'vd_ip' :  vd_data['vd_ip'], 'vd_rest_port': vd_data['vd_rest_port'],
               'auth': vd_data['auth']
    }
    [out, resp_str] = common.newcall(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
    if len(resp_str) > 3:
      jstr = json.loads(resp_str)
      mlog.info("IPSEC VPN Profile = {0}".format(json.dumps(jstr,indent=4)))
      old_p_cntlr = get_old_peer_controller_name(2)
      new_p_cntlr = get_new_peer_controller_name(2)
      found = 0
      if "vpn-profile" in jstr: 
        for vpn in jstr["vpn-profile"] :
          if vpn["name"] == (old_p_cntlr["name"] + "-Profile"):
            vpn['name'] = new_p_cntlr["controllerName"]
            if "local-auth-info" in vpn:
              # Key
              a = vpn["local-auth-info"]['key']
              if a.find("$v_") > 0:
                a=re.sub(old_p_cntlr["name"], new_p_cntlr["controllerName"], a, count=0,flags=0)
                vpn["local-auth-info"]['key'] = a
              else:
                vpn["local-auth-info"]['key'] = ('{$v_' + cust.data["custName"] + "_" + new_p_cntlr["controllerName"]
                                    + '-Profile_Local_auth_email_key__IKELKey}')
              # Email identifier
              b = vpn["local-auth-info"]['id-string']
              if b.find("$v_") > 0:
                b=re.sub(old_p_cntlr["name"], new_p_cntlr["controllerName"], b, count=0,flags=0)
                vpn["local-auth-info"]['id-string'] = b
              else:
                vpn["local-auth-info"]['id-string'] = ('{$v_' + cust.data["custName"] + "_" + new_p_cntlr["controllerName"]
                             + '-Profile_Local_auth_email_identifier__IKELIdentifier}')
              #vpn["local-auth-info"]['key'] = device["local_auth_key"]
              #vpn["local-auth-info"]['id-string'] = device["local_auth_identity"]
              #vpn["local-auth-info"]['key'] = a
              #vpn["local-auth-info"]['id-string'] = b
              found = found + 1
            if "peer-auth-info" in vpn:
              vpn["peer-auth-info"]["id-string"] = device["remote_auth_identity"]
              found = found + 1
            if found == 2: break

        # Only send the PATCH if we found all our elements
        if found == 2:
          payload = json.dumps(jstr)
          vdict = {}
          uri =  _uri.rsplit('?',1)[0]
          uri = uri + "?unhide=deprecated"
          vdict = {'body': payload, 'resp': resp, 'resp2': resp2, 'method': 'PATCH', 'uri': uri,
                'vd_ip' :  vd_data['vd_ip'], 'vd_rest_port': vd_data['vd_rest_port'],
                 'auth': vd_data['auth']
          }
          mlog.info("Sending PATCH from function {0}".format(get_ipsec_vpn_profile.__name__))
          [out, resp_str] = common.newcall(vdict,content_type='json',ncs_cmd="no",jsonflag=1)

          if len(resp_str) > 3:
            jstr = json.loads(resp_str)
            mlog.info("IPSEC VPN Profile after PATCH = {0}".format(json.dumps(jstr,indent=4)))

          if out == 1:
            payload = {}
            vdict = {}
            uri =  _uri.rsplit('?',1)[0]
            uri =  uri + "/" + old_p_cntlr["name"] + "-Profile"
            vdict = {'body': payload, 'resp': resp, 'resp2': resp2, 'method': 'DELETE', 'uri': uri,
                  'vd_ip' :  vd_data['vd_ip'], 'vd_rest_port': vd_data['vd_rest_port'],
                   'auth': vd_data['auth']
            }
            mlog.info("Sending DELETE from function {0}".format(get_ipsec_vpn_profile.__name__))
            [out, resp_str] = common.newcall(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
            get_n_fill_bind_data(_method, _uri, _payload,resp='200',vd_data=vd_data, device=device)
          else:
            mlog.error("Not Sending DELETE from function {0}".format(get_ipsec_vpn_profile.__name__))
        else:
          mlog.error("Not Sending PATCH from function {0}".format(get_ipsec_vpn_profile.__name__))
    else : 
      mlog.error("Not Sending PATCH from function {0}".format(get_ipsec_vpn_profile.__name__))
    return ''

def find_wan( _str):
  found = 0
  for i in glbl.vnms.data['wanNtwk']:
    if _str in i["name"]:
      found = 1
      break
  if found == 1: 
    return i["name"]
  else:
    return None


def get_device_system_controller( _method, _uri, _payload,resp='200',vd_data=None, device=None, newdict=None,_cntlr=2):
    global vnms, analy, cntlr, cust, mlog

    if device is None or vd_data is None :
      mlog.error("Bad inputs in function {0} ".format(get_device_system_controller.__name__))
      return

    mlog.warn("Modifying System Controller details for device = {0} ".format(device["name"]))
    resp2 = '202'
    vdict = {}
    vdict = {'body': _payload, 'resp': resp, 'resp2': resp2, 'method': _method, 'uri': _uri,
              'vd_ip' :  vd_data['vd_ip'], 'vd_rest_port': vd_data['vd_rest_port'],
               'auth': vd_data['auth']
    }
    [out, resp_str] = common.newcall(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
    if len(resp_str) > 3:
      jstr = json.loads(resp_str)
      mlog.info("System Controller = {0}".format(json.dumps(jstr,indent=4)))
      old_p_cntlr = get_old_peer_controller_name(_cntlr)
      new_p_cntlr = get_new_peer_controller_name(_cntlr)
      # first let us do the delete
      payload = {}
      vdict = {}
      uri =  _uri.rsplit('?',1)[0]
      uri =  uri + "/" + old_p_cntlr["name"] 
      vdict = {'body': payload, 'resp': resp, 'resp2': resp2, 'method': 'DELETE', 'uri': uri,
                  'vd_ip' :  vd_data['vd_ip'], 'vd_rest_port': vd_data['vd_rest_port'],
                   'auth': vd_data['auth']
      }
      [out, resp_str] = common.newcall(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
      if len(resp_str) > 3:
        newjstr = json.loads(resp_str)
        #mlog.info("System Controller = {0}".format(json.dumps(newjstr,indent=4)))

      if "controller" in jstr:
        for i in jstr["controller"] :
          if i['name'] != old_p_cntlr["name"] :
            jstr["controller"].remove(i)

        found = 0
        for i in jstr["controller"] :
          if i['name'] == old_p_cntlr["name"] :
            i['name'] = new_p_cntlr["controllerName"]
            i["site-name"] = new_p_cntlr["controllerName"]
            if "transport-addresses" in i and "transport-address" in i["transport-addresses"]:
                for j in  i["transport-addresses"]["transport-address"]:
                  if "Internet" in j["transport-domains"]:
                    j['name'] = new_p_cntlr["controllerName"] + '-Transport-INET'
                    j['ip-address'] = new_p_cntlr["inet_public_ip_address"]
                    found = found + 1
                    mlog.info("Added INET pulic IP: {0}".format(new_p_cntlr["inet_public_ip_address"]))
                  elif "MPLS" in j["transport-domains"]:
                    #elif len(j["transport-domains"]) > 1  and "mpls_public_ip_address" in new_p_cntlr:
                    j['name'] = new_p_cntlr["controllerName"] + '-Transport-MPLS'
                    j['ip-address'] = new_p_cntlr["mpls_public_ip_address"]
                    found = found + 1
                    mlog.info("Added MPLS pulic IP: {0}".format(new_p_cntlr["mpls_public_ip_address"]))
                  else:
                    mlog.error("Unidentified Transport Domain:{0} ".format(' '.join(j["transport-domains"])))
                    
        if found > 0 : 
          # since we are doing a POST we now need to remove the list
          newjstr = {}
          newjstr = { "controller" : jstr["controller"][0] }
          payload = json.dumps(newjstr)
          vdict = {}
          uri =  _uri.rsplit('?',1)[0]
          # For POST to work properly we need to modify the uri too
          uri =  uri.rsplit('/',1)[0]
          vdict = {'body': payload, 'resp': resp, 'resp2': resp2, 'method': 'POST', 'uri': uri,
                'vd_ip' :  vd_data['vd_ip'], 'vd_rest_port': vd_data['vd_rest_port'],
                 'auth': vd_data['auth']
          }
          [out, resp_str] = common.newcall(vdict,content_type='json',ncs_cmd="no",jsonflag=1)

          if len(resp_str) > 3:
            jstr = json.loads(resp_str)
            mlog.info("System Controller after PATCH = {0}".format(json.dumps(jstr,indent=4)))

          [out, resp_str] = common.newcall(newdict,content_type='json',ncs_cmd="no",jsonflag=1)
        else: 
          mlog.error("Could not find anything to add in function {0} for device = {1} ".format(get_system_controller.__name__,device["name"] ))
    else:
      mlog.error("Could not send PATCH from function {0} for device = {1} ".format(get_system_controller.__name__,device["name"] ))

    return ''

def get_system_controller( _method, _uri, _payload,resp='200',vd_data=None, device=None):
    global vnms, analy, cntlr, cust, mlog

    if device is None or vd_data is None :
      mlog.error("Bad inputs in function {0} ".format(get_system_controller.__name__))
      return

    mlog.info("In function {0} with device = {1} ".format(get_system_controller.__name__, device["name"]))
    resp2 = '202'
    vdict = {}
    vdict = {'body': _payload, 'resp': resp, 'resp2': resp2, 'method': _method, 'uri': _uri,
              'vd_ip' :  vd_data['vd_ip'], 'vd_rest_port': vd_data['vd_rest_port'],
               'auth': vd_data['auth']
    }
    [out, resp_str] = common.newcall(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
    if len(resp_str) > 3:
      jstr = json.loads(resp_str)
      mlog.info("System Controller = {0}".format(json.dumps(jstr,indent=4)))
      old_p_cntlr = get_old_peer_controller_name(2)
      new_p_cntlr = get_new_peer_controller_name(2)
      if "controller" in jstr:
        found = 0
        for i in jstr["controller"] :
          if i['name'] == old_p_cntlr["name"] :
            i['name'] = new_p_cntlr["controllerName"]
            i["site-name"] = new_p_cntlr["controllerName"]
            if "transport-addresses" in i and "transport-address" in i["transport-addresses"]:
                for j in  i["transport-addresses"]["transport-address"]:
                  if "Internet" in j["transport-domains"]:
                    j['name'] = new_p_cntlr["controllerName"] + '-Transport-INET'
                    j['ip-address'] = new_p_cntlr["inet_public_ip_address"]
                    found = found + 1
                    mlog.info("Added INET pulic IP: {0}".format(new_p_cntlr["inet_public_ip_address"]))
                  elif "MPLS" in j["transport-domains"]:
                    #elif len(j["transport-domains"]) > 1  and "mpls_public_ip_address" in new_p_cntlr:
                    j['name'] = new_p_cntlr["controllerName"] + '-Transport-MPLS'
                    j['ip-address'] = new_p_cntlr["mpls_public_ip_address"]
                    found = found + 1
                    mlog.info("Added MPLS pulic IP: {0}".format(new_p_cntlr["mpls_public_ip_address"]))
                  else:
                    mlog.error("Unidentified Transport Domain:{0} ".format(' '.join(j["transport-domains"])))
                    
        if found > 0 : 
          payload = json.dumps(jstr)
          vdict = {}
          uri =  _uri.rsplit('?',1)[0]
          vdict = {'body': payload, 'resp': resp, 'resp2': resp2, 'method': 'PATCH', 'uri': uri,
                'vd_ip' :  vd_data['vd_ip'], 'vd_rest_port': vd_data['vd_rest_port'],
                 'auth': vd_data['auth']
          }
          [out, resp_str] = common.newcall(vdict,content_type='json',ncs_cmd="no",jsonflag=1)

          if len(resp_str) > 3:
            jstr = json.loads(resp_str)
            mlog.info("System Controller after PATCH = {0}".format(json.dumps(jstr,indent=4)))

          if out == 1:
            payload = {}
            vdict = {}
            uri =  uri + "/" + old_p_cntlr["name"] 
            vdict = {'body': payload, 'resp': resp, 'resp2': resp2, 'method': 'DELETE', 'uri': uri,
                  'vd_ip' :  vd_data['vd_ip'], 'vd_rest_port': vd_data['vd_rest_port'],
                   'auth': vd_data['auth']
            }
            [out, resp_str] = common.newcall(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
          else:
            mlog.error("Not Sending DELETE from function {0} for device = {1} ".format(get_system_controller.__name__,device["name"]))
        else: 
          mlog.error("Could not find anything to add in function {0} for device = {1} ".format(get_system_controller.__name__,device["name"] ))
    else:
      mlog.error("Could not send PATCH from function {0} for device = {1} ".format(get_system_controller.__name__,device["name"] ))

    return ''


def get_device_sdwan_controller( _method, _uri, _payload,resp='200',vd_data=None, device=None,_cntlr=2):
    global vnms, analy, cntlr, cust, mlog

    if device is None or vd_data is None :
      mlog.error("Bad inputs in function {0} ".format(get_device_sdwan_controller.__name__))
      return

    mlog.warn("Modifying SDWAN Controller details for device = {0} ".format(device["name"]))
    resp2 = '202'
    vdict = {}
    vdict = {'body': _payload, 'resp': resp, 'resp2': resp2, 'method': _method, 'uri': _uri,
              'vd_ip' :  vd_data['vd_ip'], 'vd_rest_port': vd_data['vd_rest_port'],
               'auth': vd_data['auth']
    }
    [out, resp_str] = common.newcall(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
    if len(resp_str) > 3:
      jstr = json.loads(resp_str)
      #mlog.info("SDWAN Controller = {0}".format(json.dumps(jstr,indent=4)))
      old_p_cntlr = get_old_peer_controller_name(_cntlr)
      new_p_cntlr = get_new_peer_controller_name(_cntlr)
      # First the delete
      payload = {}
      vdict = {}
      uri =  _uri.rsplit('?',1)[0]
      uri =  uri + "/" + old_p_cntlr['name'] 
      vdict = {'body': payload, 'resp': resp, 'resp2': resp2, 'method': 'DELETE', 'uri': uri,
            'vd_ip' :  vd_data['vd_ip'], 'vd_rest_port': vd_data['vd_rest_port'],
             'auth': vd_data['auth']
      }
      [out, resp_str] = common.newcall(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
      if len(resp_str) > 3:
        newjstr = json.loads(resp_str)
        #mlog.info("SDWAN Controller = {0}".format(json.dumps(newjstr,indent=4)))

      if "controller" in jstr:
        found = 0

        for i in jstr["controller"] :
          if i['name'] != old_p_cntlr['name'] :
            jstr["controller"].remove(i)

        for i in jstr["controller"] :
          if i['name'] == old_p_cntlr['name'] :
            i['name'] = new_p_cntlr["controllerName"]
            found = found + 1

      if found > 0 :
        newjstr = {}
        newjstr = { "controller" : jstr["controller"][0] }
        payload = json.dumps(newjstr)
        #payload = json.dumps(jstr)
        vdict = {}
        uri =  _uri.rsplit('?',1)[0]
        # For POST to work properly we need to modify the uri too
        uri =  uri.rsplit('/',1)[0]
        vdict = {'body': payload, 'resp': resp, 'resp2': resp2, 'method': 'POST', 'uri': uri,
              'vd_ip' :  vd_data['vd_ip'], 'vd_rest_port': vd_data['vd_rest_port'],
               'auth': vd_data['auth']
        }
        # we will not call the Rest API but return the vdict
        return vdict
        '''
        [out, resp_str] = common.newcall(vdict,content_type='json',ncs_cmd="no",jsonflag=1)

        if len(resp_str) > 3:
          jstr = json.loads(resp_str)
          mlog.info("SDWAN Controller after PATCH = {0}".format(json.dumps(jstr,indent=4)))
        return vdict

        if out == 1: 
          payload = {}
          vdict = {}
          uri =  uri + "/" + old_p_cntlr['name'] 
          vdict = {'body': payload, 'resp': resp, 'resp2': resp2, 'method': 'DELETE', 'uri': uri,
                'vd_ip' :  vd_data['vd_ip'], 'vd_rest_port': vd_data['vd_rest_port'],
                 'auth': vd_data['auth']
          }
          [out, resp_str] = common.newcall(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
        else:
          mlog.error("Not Sending DELETE from function {0} for device = {1} ".format(get_sdwan_controller.__name__,device["name"]))
        '''
      else : 
        mlog.error("Could not find anything to add in function {0} for device = {1} ".format(get_sdwan_controller.__name__,device["name"] ))

    else: 
      mlog.error("Could not send PATCH from function {0} for device = {1} ".format(get_sdwan_controller.__name__,device["name"] ))
    return ''

def get_sdwan_controller( _method, _uri, _payload,resp='200',vd_data=None, device=None):
    global vnms, analy, cntlr, cust, mlog

    if device is None or vd_data is None :
      mlog.error("Bad inputs in function {0} ".format(get_sdwan_controller.__name__))
      return

    mlog.info("In function {0} with device = {1} ".format(get_sdwan_controller.__name__, device["name"]))
    resp2 = '202'
    vdict = {}
    vdict = {'body': _payload, 'resp': resp, 'resp2': resp2, 'method': _method, 'uri': _uri,
              'vd_ip' :  vd_data['vd_ip'], 'vd_rest_port': vd_data['vd_rest_port'],
               'auth': vd_data['auth']
    }
    [out, resp_str] = common.newcall(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
    if len(resp_str) > 3:
      jstr = json.loads(resp_str)
      mlog.info("SDWAN Controller = {0}".format(json.dumps(jstr,indent=4)))
      old_p_cntlr = get_old_peer_controller_name(2)
      new_p_cntlr = get_new_peer_controller_name(2)
      if "controller" in jstr:
        found = 0
        for i in jstr["controller"] :
          if i['name'] == old_p_cntlr['name'] :
            i['name'] = new_p_cntlr["controllerName"]
            found = found + 1

      if found > 0 :
        payload = json.dumps(jstr)
        vdict = {}
        uri =  _uri.rsplit('?',1)[0]
        vdict = {'body': payload, 'resp': resp, 'resp2': resp2, 'method': 'PATCH', 'uri': uri,
              'vd_ip' :  vd_data['vd_ip'], 'vd_rest_port': vd_data['vd_rest_port'],
               'auth': vd_data['auth']
        }
        [out, resp_str] = common.newcall(vdict,content_type='json',ncs_cmd="no",jsonflag=1)

        if len(resp_str) > 3:
          jstr = json.loads(resp_str)
          mlog.info("SDWAN Controller after PATCH = {0}".format(json.dumps(jstr,indent=4)))

        if out == 1: 
          payload = {}
          vdict = {}
          uri =  uri + "/" + old_p_cntlr['name'] 
          vdict = {'body': payload, 'resp': resp, 'resp2': resp2, 'method': 'DELETE', 'uri': uri,
                'vd_ip' :  vd_data['vd_ip'], 'vd_rest_port': vd_data['vd_rest_port'],
                 'auth': vd_data['auth']
          }
          [out, resp_str] = common.newcall(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
        else:
          mlog.error("Not Sending DELETE from function {0} for device = {1} ".format(get_sdwan_controller.__name__,device["name"]))
      else : 
        mlog.error("Could not find anything to add in function {0} for device = {1} ".format(get_sdwan_controller.__name__,device["name"] ))

    else: 
      mlog.error("Could not send PATCH from function {0} for device = {1} ".format(get_sdwan_controller.__name__,device["name"] ))
    return ''

def get_device_vnf_manager( _method, _uri, _payload,resp='200',vd_data=None, device=None,_cntlr=2):
    global vnms, analy, cntlr, cust, mlog

    if device is None or vd_data is None :
      mlog.error("Bad inputs in function {0} ".format(get_device_vnf_manager.__name__))
      return

    mlog.warn("Modifying VNF Manager details for device = {0} ".format(device["name"]))
    resp2 = '202'
    vdict = {}
    vdict = {'body': _payload, 'resp': resp, 'resp2': resp2, 'method': _method, 'uri': _uri,
              'vd_ip' :  vd_data['vd_ip'], 'vd_rest_port': vd_data['vd_rest_port'],
               'auth': vd_data['auth']
    }
    [out, resp_str] = common.newcall(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
    if len(resp_str) > 3:
      south_ip = [i['director_southIP'] + "/32" for i in glbl.vnms.data['director']]
      jstr = json.loads(resp_str)
      #mlog.info("VNF Manager Info = {0}".format(json.dumps(jstr,indent=4)))
      if "vnf-manager" in jstr and "ip-addresses" in jstr["vnf-manager"]:
        if _cntlr == 2:
          x= jstr["vnf-manager"]["ip-addresses"] + south_ip 
        else: 
          x= south_ip 
        jstr["vnf-manager"]["ip-addresses"] = x
        #del jstr["vnf-manager"]["vnf-manager"]
        payload = json.dumps(jstr)
        vdict = {'body': payload, 'resp': resp, 'resp2': resp2, 'method': 'PUT', 'uri': _uri,
              'vd_ip' :  vd_data['vd_ip'], 'vd_rest_port': vd_data['vd_rest_port'],
               'auth': vd_data['auth']
        }
        [out, resp_str] = common.newcall(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
        if len(resp_str) > 3:
          jstr = json.loads(resp_str)
          mlog.info("VNF Manager after PUT = {0}".format(json.dumps(jstr,indent=4)))
        if _cntlr == 2:
          newuri = '/api/config/devices/template/' + device['poststaging-template'] + '/config/system/vnf-manager'
          vdict = {'body': payload, 'resp': resp, 'resp2': resp2, 'method': 'GET', 'uri': newuri,
              'vd_ip' :  vd_data['vd_ip'], 'vd_rest_port': vd_data['vd_rest_port'],
               'auth': vd_data['auth']
          }
          [out, resp_str] = common.newcall(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
          if len(resp_str) > 3:
            jstr = json.loads(resp_str)
            #mlog.info("VNF Manager Info = {0}".format(json.dumps(jstr,indent=4)))
            if "vnf-manager" in jstr and "ip-addresses" in jstr["vnf-manager"]:
              jstr["vnf-manager"]["ip-addresses"] = south_ip
              del jstr["vnf-manager"]["vnf-manager"]
              payload = json.dumps(jstr)
              vdict = {'body': payload, 'resp': resp, 'resp2': resp2, 'method': 'PUT', 'uri': newuri,
                    'vd_ip' :  vd_data['vd_ip'], 'vd_rest_port': vd_data['vd_rest_port'],
                     'auth': vd_data['auth']
              }
              [out, resp_str] = common.newcall(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
              if len(resp_str) > 3:
                jstr = json.loads(resp_str)
                mlog.info("VNF Manager Template after PUT = {0}".format(json.dumps(jstr,indent=4)))

    return ''

def get_vnf_manager( _method, _uri, _payload,resp='200',vd_data=None, device=None):
    global vnms, analy, cntlr, cust, mlog

    if device is None or vd_data is None :
      mlog.error("Bad inputs in function {0} ".format(get_vnf_manager.__name__))
      return

    mlog.info("In function {0} with device = {1} ".format(get_vnf_manager.__name__, device["name"]))
    resp2 = '202'
    vdict = {}
    vdict = {'body': _payload, 'resp': resp, 'resp2': resp2, 'method': _method, 'uri': _uri,
              'vd_ip' :  vd_data['vd_ip'], 'vd_rest_port': vd_data['vd_rest_port'],
               'auth': vd_data['auth']
    }
    [out, resp_str] = common.newcall(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
    if len(resp_str) > 3:
      south_ip = [i['director_southIP'] + "/32" for i in glbl.vnms.data['director']]
      jstr = json.loads(resp_str)
      mlog.info("VNF Manager Info = {0}".format(json.dumps(jstr,indent=4)))
      if "vnf-manager" in jstr and "ip-addresses" in jstr["vnf-manager"]:
        x= jstr["vnf-manager"]["ip-addresses"] + south_ip 
        jstr["vnf-manager"]["ip-addresses"] = x
        del jstr["vnf-manager"]["vnf-manager"]
        payload = json.dumps(jstr)
        vdict = {'body': payload, 'resp': resp, 'resp2': resp2, 'method': 'PUT', 'uri': _uri,
              'vd_ip' :  vd_data['vd_ip'], 'vd_rest_port': vd_data['vd_rest_port'],
               'auth': vd_data['auth']
        }
        [out, resp_str] = common.newcall(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
        if len(resp_str) > 3:
          jstr = json.loads(resp_str)
          mlog.info("VNF Manager after Delete = {0}".format(json.dumps(jstr,indent=4)))
    return ''

def create_dns_config( _method, _uri,_payload,resp='200'):
    vdict = {}
    vdict = {'body': _payload, 'resp': resp, 'method': _method, 'uri': _uri}
    [out, resp_str] = common.newcall(vdict,content_type='json',ncs_cmd="no")
    if len(resp_str) > 3:
      print(json.loads(resp_str))
    return ''

def choose_template_vs_device():
    return 1
    '''
    while 1:
      num=int(input("Choose Template (0) or Device (1): "))  
      if num == 0: return 0
      elif num == 1: return 1 
      else:
        print("Re-enter 0 or 1 to continue")
    '''

def device_connect(vd_data,device=None,_cntlr=2):
    global vnms, analy, cntlr, cust, admin, auth, debug, mlog
    resp = '200'
    resp2 = '202'
    _uri = "/api/config/devices/device/" + device["name"] + "/_operations/connect"
    mlog.warn("Director with IP {0} is trying  to connect to device {1}. Please be patient".format(vd_data['vd_ip'],device["name"]))
    _payload = {}
    vdict = {}
    vdict = {'body': _payload, 'resp': resp, 'resp2': resp2, 'method': "POST", 'uri': _uri,
            'vd_ip' :  vd_data['vd_ip'], 'vd_rest_port': vd_data['vd_rest_port'],
             'auth': vd_data['auth']
    }
    found = 0
    for i in range(0,10):
      time.sleep(5)
      [out, resp_str] = common.newcall(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
      if out == 1:
        if len(resp_str) > 3:
          jstr = json.loads(resp_str)
          if "output" in jstr and "result" in  jstr["output"] and jstr["output"]["result"] == 1: 
            mlog.warn("Director with IP {0} is able to connect to device {1} for Controlller {2}".format(vd_data['vd_ip'],device["name"],str(_cntlr)))
            found = 1
            break

    if found == 0:
      mlog.error("Director with IP {0} is NOT able to connect to device {1} for Controlller {2}".format(vd_data['vd_ip'],device["name"],str(_cntlr)))
      return

    if _cntlr == 2:
      _payload = {}
      _uri = "/api/config/devices/device/" + device["name"] + "/_operations/sync-from"
      vdict = {'body': _payload, 'resp': resp, 'resp2': resp2, 'method': "POST", 'uri': _uri,
              'vd_ip' :  vd_data['vd_ip'], 'vd_rest_port': vd_data['vd_rest_port'],
               'auth': vd_data['auth']
      }
      [out, resp_str] = common.newcall(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
      if out == 1: 
        if len(resp_str) > 3:
          jstr = json.loads(resp_str)
          if "output" in jstr and "result" in  jstr["output"] and jstr["output"]["result"] == 1: 
            mlog.info("Sync from Director with IP {0} successful for device {1}".format(vd_data['vd_ip'],device["name"]))
            device["status"] = "C2-Complete"
            return
      else:
        mlog.error("Sync from Director with IP {0} NOT successful for device {1}".format(vd_data['vd_ip'],device["name"]))
        return
    else: 
      device["status"] = "C12-Complete"
      mlog.warn("Device migration sucessfull for device {0}".format(device["name"]))
      return

def get_n_process_appliance_list( vd_data):
    global vnms, analy, cntlr, cust, admin, auth, debug, mlog
    resp = '200'
    resp2 = '202'
    _uri = "/vnms/appliance/appliance"
    _payload = {}
    vdict = {}

    count = 0
    totalcnt = -1
    while 1:
      newuri = _uri + "?offset={0}&limit=25".format(count) 
      vdict = {'body': _payload, 'resp': resp, 'resp2': resp2, 'method': "GET", 'uri': newuri,
              'vd_ip' :  vd_data['vd_ip'], 'vd_rest_port': vd_data['vd_rest_port'],
               'auth': vd_data['auth']
      }
      [out, resp_str] = common.newcall(vdict,content_type='json',ncs_cmd="no",jsonflag=1)
      if len(resp_str) > 3:
        jstr = json.loads(resp_str)
        if "versanms.ApplianceStatusResult" in jstr: 
          if count == 0 and totalcnt == -1:
            if "totalCount" in jstr["versanms.ApplianceStatusResult"] : 
              totalcnt = int(jstr["versanms.ApplianceStatusResult"]["totalCount"])
            else: sys.exit("did not get totalCount")

          if "appliances" in jstr["versanms.ApplianceStatusResult"]:
            newjstr = jstr["versanms.ApplianceStatusResult"]["appliances"]
            for dev in newjstr:
              for j in range( len(glbl.vnms.data['devices'])):
                if dev["name"] == glbl.vnms.data['devices'][j]["name"]:
                    #mlog.info("Found device in list {0} ".format(dev["name"]))
                    glbl.vnms.data['devices'][j]["deviceStatus"] = {}
                    glbl.vnms.data['devices'][j]["deviceStatus"]["ping-status"] = dev["ping-status"]
                    glbl.vnms.data['devices'][j]["deviceStatus"]["sync-status"] = dev["sync-status"]
                    
        if totalcnt <= (count + 25): break
        else: count = count + 25
    write_outfile(glbl.vnms,glbl.analy,glbl.cntlr,glbl.cust, glbl.admin)
    # Find and print the error list
    errorlist = filter(lambda x: "deviceStatus" in x and (x['deviceStatus']["ping-status"]!= "REACHABLE" or x['deviceStatus']["sync-status"]!= "IN_SYNC"), glbl.vnms.data["devices"])
    if len(errorlist) > 0:
      print ("The following devices are in error status from Director = {0}".format(vd_data['vd_ip']))
      print("-" * (4+30+15+15))
      print("|{0:<{col0}}|{1:<{col1}}|{2:<{col2}}|".format("Name","DeviceStatus","SyncStatus",
                        col0=30,col1=15,col2=15))
      print("-" * (4+30+15+15))
      for v in errorlist:
        print("|{0:<{col0}}|{1:<{col1}}|{2:<{col2}}|".format(v["name"],
                        v['deviceStatus']['ping-status'],
                        v['deviceStatus']['sync-status'],
                        col0=30,col1=15,col2=15))
      print("-" * (4+30+15+15))
      print("If you proceed the above devices will NOT be migrated\n" +
            "Once the above devices are reachable you can rerun the script\n")
      ret = yes_or_no2("To continue press y and to exit press n : " )
      if ret == 0 : sys.exit("Exiting")
      elif ret == 2: pass
    # if we are here we are continuing or there are no errors. 
    #We now need to create a new list of ONLY the devices that need migration
    new_device_list = filter(lambda x: "deviceStatus" in x and (x['deviceStatus']["ping-status"] == "REACHABLE" and x['deviceStatus']["sync-status"] == "IN_SYNC"), glbl.vnms.data["devices"])
    # we will overwrite even if anything is present from before
    glbl.vnms.data["newdevicelist"] = []  
    glbl.vnms.data["newdevicelist"] = new_device_list
    write_outfile(glbl.vnms,glbl.analy,glbl.cntlr,glbl.cust, glbl.admin)
    return

def get_devices_list(option=0):
    global vnms, analy, cntlr, cust, admin, auth, debug, mlog
    cnt_list = []
    count = 1
    pcol1=0
    pcol2=0
    pcol3=0
    for i in range(len(glbl.vnms.data['newdevicelist'])):
      if len(glbl.vnms.data["newdevicelist"][i]["name"]) > pcol1 : pcol1= len(glbl.vnms.data["newdevicelist"][i]["name"]) + 1 
      if len(glbl.vnms.data["newdevicelist"][i]['poststaging-template']) > pcol2 : pcol2= len(glbl.vnms.data["newdevicelist"][i]['poststaging-template']) + 1
      if len(glbl.vnms.data["newdevicelist"][i]['dg-group']) > pcol3 : pcol3= len(glbl.vnms.data["newdevicelist"][i]['dg-group']) + 1 
      cnt_list.append(count)
      count = count + 1
    comb_dict=dict(zip(cnt_list,glbl.vnms.data['newdevicelist']))

    print("-" * (4+pcol1+pcol2+pcol3+15+6))
    print("|{0:<{col0}}|{1:<{col1}}|{2:<{col2}}|{3:<{col3}}|{4:<{col4}}|".format("Idx","Name","P-STemplate","DG-Group","Status",
                                              col0=4,col1=pcol1,col2=pcol2,col3=pcol3,col4=15))
    print("-" * (4+pcol1+pcol2+pcol3+15+6))
    for _key,v in comb_dict.items():
      if "status" in v:
        print("|{0:<{col0}}|{1:<{col1}}|{2:<{col2}}|{3:<{col3}}|{green}{4:<{col4}}{endc}|".format(_key,v['name'],v['poststaging-template'],
                      v['dg-group'],v['status'],green=bcolors.OKGREEN,endc=bcolors.ENDC,
                      col0=4,col1=pcol1,col2=pcol2,col3=pcol3,col4=15))
      else : 
        print("|{0:<{col0}}|{1:<{col1}}|{2:<{col2}}|{3:<{col3}}|{warn}{4:<{col4}}{endc}|".format(_key,v['name'],v['poststaging-template'],
                      v['dg-group'],"NotComplete",warn=bcolors.OKWARN,endc=bcolors.ENDC,
                      col0=4,col1=pcol1,col2=pcol2,col3=pcol3,col4=15))
    print("-" * (4+pcol1+pcol2+pcol3+15+6))
    while 1:
      if option == 0:
        _str = "Choose a number to continue moving Controller-2 or enter 0 to start moving Controller-1 : "
      else : 
        _str = "Choose a number to continue moving Controller-1 or enter 0 to quit the program : "
      num=int(input(_str))
      if num == 0: return None
      elif num in comb_dict:
        if (option == 0 and "status" in comb_dict[num] and  
              (comb_dict[num]["status"] == "C2-Complete" or comb_dict[num]["status"] == "C12-Complete")):
          print("Controller 2 Migration is complete. Re-enter a different the number to continue")
        elif option == 1 and "status" in comb_dict[num] and comb_dict[num]["status"] == "C12-Complete":
          print("Controller 1 and 2 Migration is complete. Re-enter a different the number to continue")
        else:  
          return comb_dict[num]
      else:
        print("Re-enter the number to continue")


def yes_or_no(question):
    reply = str(raw_input(question+' (y[default]/n/s): ')).lower().strip()
    if reply[0] == 'n': return 0
    elif reply[0] == 'y': return 1
    elif reply[0] == 's': return 2
    else:
        return yes_or_no("Did not understand input: Please re-enter ") 

def yes_or_no2(question):
    reply = str(raw_input(question+' (y/n): ')).lower().strip()
    if reply[0] == 'n': return 0
    elif reply[0] == 'y': return 1
    else:
        return yes_or_no2("Did not understand input: Please re-enter ") 

def main():
    #global vnms, analy, cntlr, cust, admin, auth, debug, mlog, mdict
    global mlog, mdict
    #mdict = readfile("in_rest.cfg")
    argcheck()
    debug = int(args['debug'])
    infile = args['file']
    LOG_FILENAME = 'vmMigrate.log'
    LOG_SIZE = 8 * 1024 * 1024
    mlog=glbl.init(infile,LOG_FILENAME, LOG_SIZE,"VMMigr3",debug)
    mlog.warn(bcolors.OKWARN + "===============Starting Phase 3 Execution==========" + bcolors.ENDC)
    if debug == 0:
        mlog.setLevel(logging.WARNING)


    write_outfile(glbl.vnms,glbl.analy,glbl.cntlr,glbl.cust, glbl.admin)

    fil = OrderedDict()
    #######################################################
    fil['GET_VNF_MANAGER.json'] = get_vnf_manager
    fil['GET_SDWAN_CONTROLLER.json'] = get_sdwan_controller
    fil['GET_SYSTEM_CONTROLLER.json'] =  get_system_controller 
    fil['GET_IPSEC_VPN_PROFILE.json'] = get_ipsec_vpn_profile
    fil['GET_DEVICE_VNF_MANAGER.json'] = get_device_vnf_manager
    fil['GET_DEVICE_SDWAN_CONTROLLER.json'] = get_device_sdwan_controller
    fil['GET_DEVICE_SYSTEM_CONTROLLER.json'] = get_device_system_controller
    fil['GET_DEVICE_IPSEC_VPN_PROFILE.json'] = get_device_ipsec_vpn_profile


    newdir= {'vd_ip' :  glbl.admin.data['new_dir']['vd_ip'],
            'vd_rest_port': glbl.admin.data['new_dir']['vd_rest_port'],
            'auth': glbl.admin.data['new_dir']['auth']
    }
    olddir= {'vd_ip' :  glbl.admin.data['old_dir']['vd_ip'],
            'vd_rest_port': glbl.admin.data['old_dir']['vd_rest_port'],
            'auth': glbl.admin.data['old_dir']['auth']
    }

    template_path = os.path.abspath(sys.argv[0]).rsplit("/",1)[0] + "/" + "in_phase3"
    template_loader = jinja2.FileSystemLoader(searchpath=template_path)
    template_env = jinja2.Environment(loader=template_loader,undefined=jinja2.StrictUndefined)
    template_env.filters['jsonify'] = json.dumps
    dir_items = sorted(os.listdir(template_path))

    get_n_process_appliance_list( olddir)
    tmpl_device = choose_template_vs_device()
    newvdict = {}
    while 1:
      mlog.warn(bcolors.OKWARN + "==============Moving Controller-2 ==========" + bcolors.ENDC)
      dev=get_devices_list()
      if dev is None: break
      for i in dir_items:
         # check the format of the files
         if not re.match(r'^\d{3}_.+\.json$', i):
            continue
         elif tmpl_device == 0 and not re.match(r'^\d1\d_.+\.json$', i):
            continue
         elif tmpl_device == 1 and not re.match(r'^\d2\d_.+\.json$', i):
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
         mlog.info("==============In {0}==========".format(_newkey))
         #ret = yes_or_no("Continue: " )
         #if ret == 0 : sys.exit("Exiting")
         #elif ret == 2: continue
         if _key[0:3] == 'GET':
           if _newkey == 'GET_CONTROLLER_WORKFLOW' or _newkey == 'GET_PEER_CONTROLLER_WORKFLOW':
             x= my_template.render()
             y= json.loads(x)
             _val(str(y['method']), str(y['path']), json.dumps(y['payload']),resp=str(y['response']),vd_data=olddir,_ofile=None)
           elif _newkey == 'GET_VNF_MANAGER':
             x= my_template.render(templateName=dev["poststaging-template"])
             y= json.loads(x)
             _val(str(y['method']), str(y['path']), json.dumps(y['payload']),resp=str(y['response']),vd_data=olddir,device=dev)
           elif _newkey == 'GET_SDWAN_CONTROLLER':
             x= my_template.render(templateName=dev["poststaging-template"])
             y= json.loads(x)
             _val(str(y['method']), str(y['path']), json.dumps(y['payload']),resp=str(y['response']),vd_data=olddir,device=dev)
           elif _newkey == 'GET_SYSTEM_CONTROLLER':
             x= my_template.render(templateName=dev["poststaging-template"])
             y= json.loads(x)
             _val(str(y['method']), str(y['path']), json.dumps(y['payload']),resp=str(y['response']),vd_data=olddir,device=dev)
           elif _newkey == 'GET_IPSEC_VPN_PROFILE':
             x= my_template.render(templateName=dev["poststaging-template"])
             y= json.loads(x)
             _val(str(y['method']), str(y['path']), json.dumps(y['payload']),resp=str(y['response']),vd_data=olddir,device=dev)
           elif _newkey == 'GET_DEVICE_SDWAN_CONTROLLER':
             x= my_template.render(deviceName=dev["name"])
             y= json.loads(x)
             newvdict = _val(str(y['method']), str(y['path']), json.dumps(y['payload']),resp=str(y['response']),vd_data=olddir,device=dev, _cntlr=2)
           elif _newkey == 'GET_DEVICE_SYSTEM_CONTROLLER':
             x= my_template.render(deviceName=dev["name"])
             y= json.loads(x)
             _val(str(y['method']), str(y['path']), json.dumps(y['payload']),resp=str(y['response']),vd_data=olddir,device=dev,newdict=newvdict, _cntlr=2)
             newvdict = {}
           elif _newkey == 'GET_DEVICE_IPSEC_VPN_PROFILE':
             x= my_template.render(deviceName=dev["name"])
             y= json.loads(x)
             _val(str(y['method']), str(y['path']), json.dumps(y['payload']),resp=str(y['response']),vd_data=olddir,device=dev, _cntlr=2)
           elif _newkey == 'GET_DEVICE_VNF_MANAGER':
             x= my_template.render(deviceName=dev["name"])
             y= json.loads(x)
             _val(str(y['method']), str(y['path']), json.dumps(y['payload']),resp=str(y['response']),vd_data=olddir,device=dev,_cntlr=2)
             # now we do a repeated connect on device from newdir
             device_connect(newdir,device=dev,_cntlr=2)
             write_outfile(glbl.vnms,glbl.analy,glbl.cntlr,glbl.cust, glbl.admin)


    dir_items = []
    dir_items = sorted(os.listdir(template_path))
    # this is where we move the Controller-1
    while 1:
      mlog.warn(bcolors.OKWARN + "==============Moving Controller-1 ==========" + bcolors.ENDC)
      dev=get_devices_list(1)
      if dev is None: break
      for i in dir_items:
         # check the format of the files
         if not re.match(r'^\d{3}_.+\.json$', i):
            continue
         elif tmpl_device == 0 and not re.match(r'^\d1\d_.+\.json$', i):
            continue
         elif tmpl_device == 1 and not re.match(r'^\d2\d_.+\.json$', i):
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
         mlog.info("==============In {0}==========".format(_newkey))
         #ret = yes_or_no("Continue: " )
         #if ret == 0 : sys.exit("Exiting")
         #elif ret == 2: continue
         if _key[0:3] == 'GET':
           if _newkey == 'GET_CONTROLLER_WORKFLOW' or _newkey == 'GET_PEER_CONTROLLER_WORKFLOW':
             x= my_template.render()
             y= json.loads(x)
             _val(str(y['method']), str(y['path']), json.dumps(y['payload']),resp=str(y['response']),vd_data=olddir,_ofile=None)
           elif _newkey == 'GET_VNF_MANAGER':
             x= my_template.render(templateName=dev["poststaging-template"])
             y= json.loads(x)
             _val(str(y['method']), str(y['path']), json.dumps(y['payload']),resp=str(y['response']),vd_data=olddir,device=dev)
           elif _newkey == 'GET_SDWAN_CONTROLLER':
             x= my_template.render(templateName=dev["poststaging-template"])
             y= json.loads(x)
             _val(str(y['method']), str(y['path']), json.dumps(y['payload']),resp=str(y['response']),vd_data=olddir,device=dev)
           elif _newkey == 'GET_SYSTEM_CONTROLLER':
             x= my_template.render(templateName=dev["poststaging-template"])
             y= json.loads(x)
             _val(str(y['method']), str(y['path']), json.dumps(y['payload']),resp=str(y['response']),vd_data=olddir,device=dev)
           elif _newkey == 'GET_IPSEC_VPN_PROFILE':
             x= my_template.render(templateName=dev["poststaging-template"])
             y= json.loads(x)
             _val(str(y['method']), str(y['path']), json.dumps(y['payload']),resp=str(y['response']),vd_data=olddir,device=dev)
           elif _newkey == 'GET_DEVICE_SDWAN_CONTROLLER':
             x= my_template.render(deviceName=dev["name"])
             y= json.loads(x)
             newvdict = _val(str(y['method']), str(y['path']), json.dumps(y['payload']),resp=str(y['response']),vd_data=newdir,device=dev, _cntlr=1)
           elif _newkey == 'GET_DEVICE_SYSTEM_CONTROLLER':
             x= my_template.render(deviceName=dev["name"])
             y= json.loads(x)
             _val(str(y['method']), str(y['path']), json.dumps(y['payload']),resp=str(y['response']),vd_data=newdir,device=dev,newdict=newvdict, _cntlr=1)
             newvdict = {}
           elif _newkey == 'GET_DEVICE_IPSEC_VPN_PROFILE':
             x= my_template.render(deviceName=dev["name"])
             y= json.loads(x)
             _val(str(y['method']), str(y['path']), json.dumps(y['payload']),resp=str(y['response']),vd_data=newdir,device=dev, _cntlr=1)
           elif _newkey == 'GET_DEVICE_VNF_MANAGER':
             x= my_template.render(deviceName=dev["name"])
             y= json.loads(x)
             _val(str(y['method']), str(y['path']), json.dumps(y['payload']),resp=str(y['response']),vd_data=newdir,device=dev, _cntlr=1)
             # now we do a repeated connect on device from newdir
             device_connect(newdir,device=dev,_cntlr=1)
             write_outfile(glbl.vnms,glbl.analy,glbl.cntlr,glbl.cust, glbl.admin)
    mlog.warn(bcolors.OKWARN + "==============Completed execution of Phase 3==========" + bcolors.ENDC)

if __name__ == "__main__":
    main()


