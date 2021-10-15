#!/usr/bin/env python3

#### DRAFT VERSION 0.0.2

import subprocess
import time
import os
import json

session_uid=""

json_db = ["""
{ "objects" : [ {
    "uid" : "97aeb44f-9aea-11d5-bd16-0090272ccb30",
    "name" : "AOL",
    "type" : "service-tcp",
    "domain" : {
      "domain-type" : "data domain",
      "uid" : "a0bbbc99-adef-4ef8-bb6d-defdefdefdef",
      "name" : "Check Point Data"
    },
    "port" : "5190"
  }, {
    "uid" : "97aeb3e9-9aea-11d5-bd16-0090272ccb30",
    "name" : "AP-Defender",
    "type" : "service-tcp",
    "domain" : {
      "domain-type" : "data domain",
      "uid" : "a0bbbc99-adef-4ef8-bb6d-defdefdefdef",
      "name" : "Check Point Data"
    },
    "port" : "2626"
  }, {
    "uid" : "97aeb3ea-9aea-11d5-bd16-0090272ccb30",
    "name" : "AT-Defender",
    "type" : "service-tcp",
    "domain" : {
      "domain-type" : "data domain",
      "uid" : "a0bbbc99-adef-4ef8-bb6d-defdefdefdef",
      "name" : "Check Point Data"
    },
    "port" : "2626"
  }, {
    "uid" : "96759a8d-aab8-43d9-bbfc-b459ce66ac87",
    "name" : "Backage",
    "type" : "service-tcp",
    "domain" : {
      "domain-type" : "data domain",
      "uid" : "a0bbbc99-adef-4ef8-bb6d-defdefdefdef",
      "name" : "Check Point Data"
    },
    "port" : "411"
  }, {
    "uid" : "1fceea78-d378-44b4-8939-019b68f48518",
    "name" : "BGP",
    "type" : "service-tcp",
    "domain" : {
      "domain-type" : "data domain",
      "uid" : "a0bbbc99-adef-4ef8-bb6d-defdefdefdef",
      "name" : "Check Point Data"
    },
    "port" : "179"
  }, {
    "uid" : "86077a7d-a8da-4b5b-919c-366fe91ad1da",
    "name" : "Bionet-Setup",
    "type" : "service-tcp",
    "domain" : {
      "domain-type" : "data domain",
      "uid" : "a0bbbc99-adef-4ef8-bb6d-defdefdefdef",
      "name" : "Check Point Data"
    },
    "port" : "5000"
  }, {
    "uid" : "11da2773-a070-4f68-a3c2-9ce5dc158683",
    "name" : "CheckPointExchangeAgent",
    "type" : "service-tcp",
    "domain" : {
      "domain-type" : "data domain",
      "uid" : "a0bbbc99-adef-4ef8-bb6d-defdefdefdef",
      "name" : "Check Point Data"
    },
    "port" : "18301"
  }, {
    "uid" : "986bad5a-94d2-4a8c-81aa-de98d3ecb5c6",
    "name" : "Citrix_ICA",
    "type" : "service-tcp",
    "domain" : {
      "domain-type" : "data domain",
      "uid" : "a0bbbc99-adef-4ef8-bb6d-defdefdefdef",
      "name" : "Check Point Data"
    },
    "port" : "1494"
  }, {
    "uid" : "97aeb451-9aea-11d5-bd16-0090272ccb30",
    "name" : "duplicate ConnectedOnLine",
    "type" : "service-tcp",
    "domain" : {
      "domain-type" : "data domain",
      "uid" : "a0bbbc99-adef-4ef8-bb6d-defdefdefdef",
      "name" : "Check Point Data"
    },
    "port" : "16384"
  }, {
    "uid" : "97aeb3ad-9aea-11d5-bd16-0090272ccb30",
    "name" : "CP_Exnet_PK",
    "type" : "service-tcp",
    "domain" : {
      "domain-type" : "data domain",
      "uid" : "a0bbbc99-adef-4ef8-bb6d-defdefdefdef",
      "name" : "Check Point Data"
    },
    "port" : "18262"
  } ], "from" : 1,
  "to" : 500,
  "total" : 999
}
""", """
{ "objects" : [ {
    "uid" : "11111111111111",
    "name" : "de",
    "type" : "service-tcp",
    "domain" : {
      "domain-type" : "data domain",
      "uid" : "a0bbbc99-adef-4ef8-bb6d-defdefdefdef",
      "name" : "Check Point Data"
    },
    "port" : "5110"
  }, {
    "uid" : "97aeb451-9aea-11d5-bd16-0090272ccb30",
    "name" : "duplicate ConnectedOnLine",
    "type" : "service-tcp",
    "domain" : {
      "domain-type" : "data domain",
      "uid" : "a0bbbc99-adef-4ef8-bb6d-defdefdefdef",
      "name" : "Check Point Data"
    },
    "port" : "16384"
  }, {
    "uid" : "aaaaaaaaea-11d5-bd16-0090272ccb30",
    "name" : "AP-Defedfdfernder",
    "type" : "service-tcp",
    "domain" : {
      "domain-type" : "data domain",
      "uid" : "a0bbbc99-adef-4ef8-bb6d-defdefdefdef",
      "name" : "Check Point Data"
    },
    "port" : "2626"
  } ], "from" : 501,
  "to" : 503,
  "total" : 999
}
""" ]
## Environment Based variables
ACCESS_POLICIES=["Global Network", "policy2 Network"]
THREAT_POLICIES=["", ""]
PATH_LOG_FILE="" # Define Log File Location if "" => it is written to stdout

## This Parameters should only be changed if its really clear what is means
MAX_OBJECT_PER_REQUEST=500
TYPE_ACCESS_RULE="access-rule"
TYPE_THREAT_RULE=""
TYPE_HOSTS="hosts"
TYPE_HOSTGROUPS = "groups"
TYPE_TCP_SERVICES = "services-tcp"
TYPE_UDP_SERVICES = "servives-udp"
TYPE_SERVICEGROUPS = "service-groups"


def run():
    var_result = tags_where_used()
    print(var_result)

def get_all_data_of_type (p_req_type, p_rulestring=""):
  log("################################################################")
  log("# get_all_data_of_type (" + p_req_type + "," + p_rulestring + ")")
  log("################################################################")
  #$rulestring = ""    # This variable is only needed for Rule specific requests
  var_offset = 0
  var_last_item_index = 0
  var_data = ""
  # get number of Objects of the given req_type
    #run_mgmt_cli(session_uid, p_req_type + " " + p_rulestring + " limit 1 ", "")
  var_mgmt_feedback = json.loads(json_db[0])
  var_object_count = var_mgmt_feedback['total']
  # make mgmt_cli show commands es much as needed
  var_data_dict = { "objects" : []}
  var_count_requests = 0
  while (var_last_item_index <= var_object_count):
    log("mgmt_cli show "+ p_req_type + " " + p_rulestring + " limit 1 offset " + str(var_offset) + " --session-id " + session_uid)
    var_json_data = json_db[var_count_requests]
    #var_data += run_bash("echo request " + str(MAX_OBJECT_PER_REQUEST) + " data-sets") #mgmt_cli show $req_type $rulestring details-level full limit MAX_OBJECT_PER_REQUEST offset $offset -s $mgmt_cli_session_file)
    var_data_dict_tmp = json.loads(var_json_data)
    log("keys" + str(var_data_dict_tmp.keys()))
    #log("var_data_dict_tmp " + str(var_data_dict_tmp))
    for obj in var_data_dict_tmp['objects']:
        var_data_dict['objects'].append(obj) # Hint Duplicates can be occur - no errors [[FIX]]
    var_offset += MAX_OBJECT_PER_REQUEST
    var_last_item_index = var_last_item_index + MAX_OBJECT_PER_REQUEST
    var_count_requests += 1
  log("announced data count: " + str(var_object_count))
  log("retrieved data count: " + str(len(var_data_dict['objects'])))
  var_data_dict = parse_obj_to_uid_dict(var_data_dict, p_req_type)
  return var_data_dict


def parse_obj_to_uid_dict(p_dict, p_pre_key):
  log("################################################################")
  log("# parse_obj_to_uid_dict (" + "" + "," + "" + ")")
  log("################################################################")
  var_new_dict = {}
  var_new_dict[p_pre_key] = {}
  for obj in p_dict["objects"]:
    log(obj)
    log("uid " + obj["uid"])
    var_uid = str(obj["uid"])
    var_new_dict[p_pre_key][var_uid] = obj
  log("parsed new dict " + str(var_new_dict))




def tags_where_used ():
    var_data = ""
    #for var_policy in ACCESS_POLICIES:
        #var_data += get_all_data_of_type(TYPE_ACCESS_RULE, "\"" + var_policy + "\"")
    #for var_policy in THREAT_POLICIES:
        #var_data += get_all_data_of_type(TYPE_THREAT_RULE, "\"" + var_policy + "\"")
    #var_data += get_all_data_of_type(TYPE_HOSTS)
    #var_data += get_all_data_of_type(TYPE_HOSTGROUPS)
    #var_data += get_all_data_of_type(TYPE_SERVICEGROUPS)
    #var_data += get_all_data_of_type(TYPE_TCP_SERVICES)
    #var_data += get_all_data_of_type(TYPE_UDP_SERVICES)
    var_data = get_all_data_of_type(TYPE_TCP_SERVICES)
    ##  [[TODO]]: GREP DATA name and uid for all Entries where the TAG ID resideds:
    return var_data

def run_bash (p_command):
  var_run = subprocess.Popen(["/bin/bash", "-c", p_command], stdout=subprocess.PIPE)
  var_output = var_run.communicate()[0].decode("utf-8")
  log(var_output)
  return var_output

def run_mgmt_cli (p_session_uid, p_command, p_after_command):
    run_bash("mgmt_cli " + p_command + "--session-id " + p_session_uid + " " + p_after_command)

def log (p_logstring):
  if (PATH_LOG_FILE != ""):
    f = open(PATH_LOG_FILE, "a")
    f.write(p_logstring)
    f.close()
  else:
    print(p_logstring)

run()
