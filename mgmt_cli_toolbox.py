#!/usr/bin/env python3

#### DRAFT VERSION 0.0.4
MANUAL = """
[./mgmt_cli_toolbox.py | mgmt_cli_toolbox.py] [-i <mgmt_cli_session_id> | -s mgmt_cli_session_file] [COMMAND] [PARAMS]

-h | --help         : show this (man) page.
-s | --session_file : not supported yet.
-i | --session_id   : mgmt_cli session-id to verify on which session the script should work
                      is needed otherwise currently no features can be used.
                      in future the session handling should be done by the script itself

COMMANDs (currently supported commands):
"""
COMMANDS = ["uuid_where_used"]

import subprocess
import time
import os
import json
import sys, getopt

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
    "uid" : "a0bbbc99-adef-4ef8-bb6d-defdefdefdef1",
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
      "uid" : "a0bbbc99-adef-4ef8-bb6d-defdefdefdef1",
      "name" : "Check Point Data"
    },
    "port" : "2626"
  } ], "from" : 501,
  "to" : 503,
  "total" : 999
}
""" ]

"""
########################################################################
#------------------------ CUSTOM PARAMETERS ---------------------------#
########################################################################
"""
## Environment Based variables
#ACCESS_POLICIES=["Global Network", "policy2 Network"]
#THREAT_POLICIES=["", ""]
#NAT_PACKAGES=["", ""]
RELEVANT_OBJECTS=["TCP_SERVICE"]
PATH_LOG_FILE="mgmt_cli_toolbox.log" # Define Log File Location if "" => it is written to stdout

"""
########################################################################
#------------------------ STATIC PARAMETERS -------------------------------------#
########################################################################
"""
## This Parameters should only be changed if its really clear what is means
MAX_OBJECT_PER_REQUEST=500
OBJ_TYPES = {
    "HOST" : { "rep" : "host", "cli_show" : "hosts", "cli_set": "host" },
    "HOST_GROUP" : { "rep" : "host_group", "cli_show" : "groups", "cli_set" : "group" },
    "TCP_SERVICE" : { "rep" : "service_tcp", "cli_show" : "services-tcp", "cli_set" : "service-tcp" },
    "UDP_SERVICE" : { "rep" : "service_udp", "cli_show" : "services-udp", "cli_set" : "service-udp" },
    "SERVICE_GROUP" : { "rep" : "service_group", "cli_show" : "hosts", "cli_set" : "host" },
    "ACCESS_RULE": { "rep" : "access_rule", "cli_show" : "access-rulebase", "cli_set" : "access-rule" },
    #"THREAT_PREV_RULE" : { "rep" : "host", "cli_get", "hosts", "cli_set", "host" },
    #"NAT_RULE" : { "rep" : "host", "cli_get", "hosts", "cli_set", "host" },
}
SYNTAX_SHOW = {}

"""
########################################################################
#------------------------ METHODS -------------------------------------#
########################################################################
"""
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
    log("mgmt_cli show "+ p_req_type + " " + p_rulestring + "details-level full limit 1 offset " + str(var_offset) + " --session-id " + "session_id")
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
  var_data_dict = add_used_by(var_data_dict)
  return var_data_dict

def parse_obj_to_uid_dict(p_dict, p_type):
  log("################################################################")
  log("# parse_obj_to_uid_dict (" + "" + "," + "" + ")")
  log("################################################################")
  var_new_dict = {}
  for obj in p_dict["objects"]:
    #log(obj)
    log("uid " + obj["uid"])
    var_uid = str(obj["uid"])
    var_new_dict[var_uid] = {}
    var_new_dict[var_uid]["obj"] = obj
    var_new_dict[var_uid]["type"] = p_type
    var_new_dict[var_uid]["as_string"] = str(obj)
  log("parsed new dict " + str(var_new_dict))
  return var_new_dict


def add_used_by (p_data_dir):
    log("################################################################")
    log("# add_used_by (" + "" + "," + "" + ")")
    log("################################################################")
    var_data = p_data_dir
    for i_key in p_data_dir:
        var_data[i_key]["used_by"] = []
        for i_key_sub in p_data_dir:
            var_string = var_data[i_key_sub]["as_string"]
            if i_key in var_string:
                if not i_key is i_key_sub:
                    var_data[i_key]["used_by"].append(i_key_sub)
    log(var_data)
    return var_data

def uuid_where_used (p_uuid):
    log("################################################################")
    log("# uuid_where_used (" + "" + "," + "" + ")")
    log("################################################################")
    combined_var_data = load_all_policy_objects()
    #combined_var_data = get_all_data_of_type(OBJ_TYPES["SERVICE_GROUP"]["cli_show"])
    log(combined_var_data)
    # Retrieve all used_by uuids for the given uid
    used_by_list = combined_var_data[p_uuid]["used_by"]
    return used_by_list

def load_all_policy_objects ():
    log("################################################################")
    log("# load_all_policy_objects (" + "" + "," + "" + ")")
    log("################################################################")
    var_data = {}
    for var_type in RELEVANT_OBJECTS:
        if var_type == "ACCESS_RULE":
            log("load Access Policy...")
        elif var_type == "THREAT_RULE":
            log("load Threat Policy...")
            #for var_policy in THREAT_POLICIES:
            #    var_data += get_all_data_of_type(TYPE_THREAT_RULE, "\"" + var_policy + "\"")
        else:
            log("load Objects of Type:" + var_type + "...")
            var_data = merge_dicts(var_data, get_all_data_of_type(var_type, ""))
    return var_data

def object_by_uid (p_uid):
    log("################################################################")
    log("# object_by_uid (" + "" + "," + "" + ")")
    log("################################################################")
    log("this function is not implemented yet")


"""
########################################################################
#------------------------ HELPERS -------------------------------------#
########################################################################
"""
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
    f.write(str(p_logstring) + "\n")
    f.close()
  else:
    print(p_logstring)

def clear_log ():
    ## If file exists, delete it ##
    if os.path.isfile(PATH_LOG_FILE):
        os.remove(PATH_LOG_FILE)
    else:    ## Show an error ##
        print("Error: %s file not found" % PATH_LOG_FILE)


"""
########################################################################
#------------------------ PYTHON - HELPERS ----------------------------#
########################################################################
"""
def merge_dicts(*dict_args):
    """
    Given any number of dictionaries, shallow copy and merge into a new dict,
    precedence goes to key-value pairs in latter dictionaries.
    """
    result = {}
    for dictionary in dict_args:
        result.update(dictionary)
    return result

"""
########################################################################
#------------------------ CLI HANDLING --------------------------------#
########################################################################
"""

def main (argv):
  var_man_page = MANUAL + str(COMMANDS)
  var_mgmt_cli_session_id = ""
  try:
    opts, args = getopt.getopt(argv,"hi:s:c:",['help', 'session_id=', 'session_file=', 'command='])
  except getopt.GetoptError:
    print(var_man_page)
    sys.exit(2)
  for opt, arg in opts:
    log("opt -> " + str(opt))
    log("arg -> " + str(arg))
    log("args -> " + str(args))
    if opt in ('-h', "--help"):
      print(var_man_page)
      sys.exit()
    if opt in ("-i", "--session_id"):
      var_mgmt_cli_session_id = arg
    #elif opt in ("-s", "--session_file"):
    #  var_mgmt_cli_session_id = ""
    if arg in COMMANDS:
      clear_log()
      log("deleted_old_log_file")
      result = globals()[str(arg)](args[0])
      print(result)

if __name__ == "__main__":
  main(sys.argv[1:])
