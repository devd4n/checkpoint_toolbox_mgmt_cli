#!/usr/bin/env python3
"""
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

"""
    Author: https://github.com/devd4n
"""

#### DRAFT VERSION 0.2.0

MANUAL = """
mgmt_cli_toolbox.py [-i <mgmt_cli_session_id> | -s <mgmt_cli_session_file>] [-p | -l] [COMMAND] [PARAMS]


-h | help         : show this (man) page.
-l | local_db     : load data from file defined via DATABASE_STORE_PATH
-p | pull         : pull data via mgmt_cli and override DATABASE_STORE_PATH
                    -> -s or -i parameter is mandatory to use this function
-s | session_file : mgmt_cli session-file (mgmt_cli login user <> > file)
-i | session_id   : mgmt_cli session-id to verify on which session the script should work
                      is needed otherwise currently no features can be used.
                      in future the session handling should be done by the script itself
-u | !username     : ! NOT SUPPORTED YET username of mgmt_cli user session_id
-p | !password     : ! NOT SUPPORTED YET password of mgmt_cli user session
-c | command      : used to run a command (supported commands are shown below)

COMMANDs (currently supported commands):
uuid_where_used <uid>
show <uid> <key1> <key2> <key3> ...
find_name <name>
"""
COMMANDS = ["uuid_where_used", "show", "find_name"]

import subprocess
import time
import os
import json
import sys, getopt
import datetime

"""
########################################################################
#------------------------ CUSTOM PARAMETERS ---------------------------#
########################################################################
"""
## Environment Based variables
ACCESS_LAYER=["Network"]
#THREAT_POLICIES=["", ""]
#NAT_PACKAGES=["", ""]
RELEVANT_OBJECTS=["TCP_SERVICE", "UDP_SERVICE", "SERVICE_GROUP", "HOST", "HOST_GROUP", "ACCESS_RULE", "TAG", "TIME", "NETWORK"]
PATH_ROOT = "./toolbox_files/"
DATABASE_STORE_PATH = PATH_ROOT + "db.json"
LOG_FILE= PATH_ROOT + "" # Define Log File Location if "" => it is written to stdout
LOG_LEVEL="TRACE"
"""
########################################################################
#------------------------ STATIC PARAMETERS -------------------------------------#
########################################################################
"""
## This Parameters should only be changed if its really clear what is means
MAX_OBJECT_PER_REQUEST=500      # This value is given by checkpoint -> Doku of Mgmt API
OBJ_TYPES = {
    "HOST" : { "rep" : "host", "cli_show" : "hosts", "cli_set": "host" },
    "HOST_GROUP" : { "rep" : "host_group", "cli_show" : "groups", "cli_set" : "group" },
    "TCP_SERVICE" : { "rep" : "service_tcp", "cli_show" : "services-tcp", "cli_set" : "service-tcp" },
    "UDP_SERVICE" : { "rep" : "service_udp", "cli_show" : "services-udp", "cli_set" : "service-udp" },
    "SERVICE_GROUP" : { "rep" : "service_group", "cli_show" : "service-groups", "cli_set" : "service-group" },
    "ACCESS_RULE": { "rep" : "access_rule", "cli_show" : "access-rulebase", "cli_set" : "access-rule" },
    "TAG" : { "rep" : "tag", "cli_show" : "tags", "cli_set" : "tag" },
    "TIME" : { "rep" : "time", "cli_show" : "times", "cli_set" : "time" },
    "NETWORK" : { "rep" : "network", "cli_show" : "networks", "cli_set" : "network" }
    #NOT SUPPORTED YET: "THREAT_PREV_RULE" : { "rep" : "host", "cli_get", "hosts", "cli_set", "host" },
    #NOT SUPPORTED YET: "THREAT_EXCEPTION" :
    #NOT SUPPORTED YET: "NAT_RULE" : { "rep" : "host", "cli_get", "hosts", "cli_set", "host" },
}
LOG_LVL = {
    "FATAL" : 1, "ERROR" : 2, "WARNING" : 3, "INFO" : 7, "DEBUG" : 8,
    "TRACE" : 9, "DETAIL-TRACE" : 10,
}
LOG_LVL_INV = {
    1 : "FATAL", 2 : "ERROR", 3 : "WARNING", 7 : "INFO", 8 : "DEBUG",
    9 : "TRACE", 10 : "DETAIL-TRACE",
}
GLOBAL_STORAGE_DICT = {}
SESSION_ID = ""

"""
########################################################################
#---------------------- API METHODS -----------------------------------#
########################################################################
"""
def uuid_where_used (args):
    log("uuid_where_used (" + str(args) + ")", LOG_LVL["TRACE"], True)
    # Retrieve all used_by uuids for the given uid
    var_uid = args[0]
    try:
        log("var_uid: " + str(var_uid))
        used_by_list = GLOBAL_STORAGE_DICT["by_uid"][var_uid]["tb_used_by"]
        return used_by_list
    except KeyError:
        log("invalid uuid: " + str(var_uid) + " - can't be found", LOG_LVL["ERROR"])

def show (args):
    log("show (" + str(args) + ")", LOG_LVL["TRACE"], True)
    dict = {}
    var_res_list = ""
    # show keys or full object from given UID
    if len(args) == 0:
        log("missing uuid for show command", LOG_LVL["ERROR"])
        return None
    elif len(args) == 1:
        dict = GLOBAL_STORAGE_DICT["by_uid"][args[0]]
    else:
        for i in range(1,len(args)):
            dict[args[i]] = GLOBAL_STORAGE_DICT["by_uid"][args[0]][args[i]]
    for val in dict.values():
        var_res_list += str(val) + ","
    return var_res_list

def append (p_uid, p_key, p_value):
    log("append (" + str(p_uuid) + "," + str(p_key) + "," + str(p_value) + ")", LOG_LVL["TRACE"], True)
    GLOBAL_STORAGE_DICT["by_uid"][p_uid][p_key] = p_value
    save()

def find_name (args):
    log("find_name (" + str(args) + ")", LOG_LVL["TRACE"], True)
    var_name = args[0]
    var_res_list = ""
    for key in GLOBAL_STORAGE_DICT["by_uid"].keys():
        log(str(GLOBAL_STORAGE_DICT["by_uid"][key]["name"]), LOG_LVL["DETAIL-TRACE"])
        if var_name == GLOBAL_STORAGE_DICT["by_uid"][key]["name"]:
            var_res_list += str(key) + ","
    return var_res_list


"""
########################################################################
#---------------------- PRIVATE METHODS -------------------------------#
########################################################################
"""

def parse_obj_to_uid_dict(p_dict, p_type):
  log("parse_obj_to_uid_dict (" + "" + "," + "" + ")", LOG_LVL["TRACE"], True)
  var_new_dict = {}
  for obj in p_dict["objects"]:
    log("uid " + obj["uid"], LOG_LVL["DETAIL-TRACE"])
    var_uid = str(obj["uid"])
    var_new_dict[var_uid] = obj
    var_new_dict[var_uid]["tb_type"] = p_type
    var_new_dict[var_uid]["tb_as_string"] = str(obj)
  log("parsed new dict " + str(var_new_dict), LOG_LVL["DETAIL-TRACE"])
  return var_new_dict


def add_used_by (p_data_dir):
    log("add_used_by (" + "p_data_dir" + "," + "" + ")", LOG_LVL["TRACE"], True)
    var_data = p_data_dir
    for i_key in p_data_dir:
        var_data[i_key]["tb_used_by"] = []
        for i_key_sub in p_data_dir:
            if i_key != i_key_sub:
              var_string = var_data[i_key_sub]["tb_as_string"]
              if i_key in var_string:
                log("where_used_finding:" + i_key + " - used by -> " + i_key_sub, LOG_LVL["DETAIL-TRACE"])
                var_data[i_key]["tb_used_by"].append(i_key_sub)
    return var_data

def object_by_uid (p_uid):
    log("# object_by_uid (" + "" + "," + "" + ")", LOG_LVL["TRACE"], True)
    log("this function is not implemented yet")

def save ():
    log("save (" + "" + "," + "" + ")", LOG_LVL["TRACE"], True)
    save_data_to_file (DATABASE_STORE_PATH, GLOBAL_STORAGE_DICT)

def load_local ():
    log("load_local (" + "" + "," + "" + ")", LOG_LVL["TRACE"], True)
    global GLOBAL_STORAGE_DICT
    log("load data from: " + DATABASE_STORE_PATH)
    GLOBAL_STORAGE_DICT = load_data_from_file(DATABASE_STORE_PATH)
    log("number of loaded dicts: " + str(len(GLOBAL_STORAGE_DICT)))


"""
########################################################################
#------------------------ API-Pull Functions --------------------------#
########################################################################
"""
def pull_all ():
    log("pull_all (" + "" + "," + "" + ")", LOG_LVL["TRACE"], True)
    var_dict = {}
    for var_type in RELEVANT_OBJECTS:
        var_data = {}
        var_data["objects"] = []
        log("load Objects of Type:" + var_type + "...")
        if var_type == "ACCESS_RULE":
            for var_layer in ACCESS_LAYER:
                var_rulestring = " name " + "\"" + var_layer + "\""
                var_data_tmp = pull_all_obj_of_type(var_type, var_rulestring)
                for obj in var_data_tmp["rulebase"]:
                    obj["tb_access-layer"] = var_layer
                    if not "name" in obj.keys():
                        obj["name"] = ""
                    var_data['objects'].append(obj)
                log("retrieved data count: " + str(len(var_data['objects'])))
                var_data = parse_obj_to_uid_dict(var_data, var_type)
                var_dict = merge_dicts(var_dict, var_data)
        else:
            var_data_tmp = pull_all_obj_of_type(var_type, "")
            for obj in var_data_tmp['objects']:
                # TODO: Duplicates can be occur - Check this - no errors [[FIX]]
                var_data["objects"].append(obj)
            log("retrieved data count: " + str(len(var_data['objects'])))
            var_data = parse_obj_to_uid_dict(var_data, var_type)
            var_dict = merge_dicts(var_dict, var_data)
    var_dict = add_used_by(var_dict)
    GLOBAL_STORAGE_DICT["by_uid"] = var_dict
    save()

def pull_all_obj_of_type (p_req_type, p_rulestring=""):
  log("pull_all_obj_of_type (" + p_req_type + "," + p_rulestring + ")", LOG_LVL["TRACE"], True)
  #rulestring = ""    # This variable is only needed for Rule specific requests
  var_offset = 0
  var_last_item_index = 0
  # how much requests are needed to retrieve all data:
  var_json_data = run_mgmt_cli(SESSION_ID, "show", (OBJ_TYPES[p_req_type]["cli_show"] + p_rulestring + " limit 1"), "")
  var_object_count = int(json.loads(var_json_data)['total'])
  # make mgmt_cli show commands es much as needed
  while (var_last_item_index <= var_object_count):
    var_mgmt_string = OBJ_TYPES[p_req_type]["cli_show"] + p_rulestring + " details-level full limit " + str(MAX_OBJECT_PER_REQUEST) + " offset " + str(var_offset)
    var_json_data = run_mgmt_cli(SESSION_ID, "show", var_mgmt_string, "")
    # Parse json data from mgmt_cli string
    var_all_obj_of_type = json.loads(var_json_data)
    log("keys_retrieved: " + str(var_all_obj_of_type.keys()), LOG_LVL["DEBUG"])
    var_offset += MAX_OBJECT_PER_REQUEST
    var_last_item_index = var_last_item_index + MAX_OBJECT_PER_REQUEST
    log("announced data count: " + str(var_object_count), LOG_LVL["DEBUG"], LOG_LVL["DEBUG"])
  return var_all_obj_of_type


"""
########################################################################
#------------------------ HELPERS -------------------------------------#
########################################################################
"""
def run_bash (p_command):
  var_run = subprocess.Popen(["/bin/bash", "-c", p_command], stdout=subprocess.PIPE)
  var_output = var_run.communicate()[0].decode("utf-8")
  if var_output.startswith("Traceback"):
      log(var_output, LOG_LVL["ERROR"])
  else:
      log(var_output, LOG_LVL["DETAIL-TRACE"])
  return var_output

def run_mgmt_cli (p_session_uid, p_action, p_command, p_after_command):
    var_command = "mgmt_cli" + " " + p_action + " " + p_command + " --session-id " + p_session_uid + p_after_command + " --format json"
    log(var_command, LOG_LVL["TRACE"])
    var_response = run_bash(var_command)
    # Raise an exception if mgmt_cli responded with an error
    if "\"code\"" in var_response:
        var_err = Exception(var_response)
        raise var_err
    elif "Failed to parse command line parameters." in var_response or "mgmt_cli command-name " in var_response:
        var_err = Exception("failed mgmt_cli parameters - check session id!\n\n")
        raise var_err
    return var_response

def save_data_to_file (p_file_name, p_dict):
 json.dump( p_dict, open( p_file_name, 'w' ) )

def load_data_from_file (p_file_name):
 return json.load(open(p_file_name))

def log (p_logstring, p_LOG_LVL=9, p_HEADLINE=False):
  if p_LOG_LVL <= LOG_LVL[LOG_LEVEL]:
      if p_HEADLINE:
          var_log_line = str(get_timestamp()) + "  |" + str(LOG_LVL_INV[p_LOG_LVL]) + ("|  ") + "################################################################ \n"
          var_log_line += str(get_timestamp()) + "  |" + str(LOG_LVL_INV[p_LOG_LVL]) + ("|  ") + str(p_logstring) + "\n"
          var_log_line += str(get_timestamp()) + "  |" + str(LOG_LVL_INV[p_LOG_LVL]) + ("|  ") + "################################################################"
      else:
          var_log_line = str(get_timestamp()) + "  |" + str(LOG_LVL_INV[p_LOG_LVL]) + ("|  ") + str(p_logstring)
      if (LOG_FILE != "" and LOG_FILE != PATH_ROOT):
          f = open(LOG_FILE, "a")
          f.write(var_log_line + "\n")
          f.close()
      else:
        print(var_log_line)

def clear_log ():
    ## If file exists, delete it ##
    if (LOG_FILE != ""  and LOG_FILE != PATH_ROOT):
      if os.path.isfile(LOG_FILE):
        os.remove(LOG_FILE)
      else:    ## Show an error ##
        log("couldn't delete log file > cause not exists on following path: " + LOG_FILE, LOG_LVL["WARNING"])

def get_timestamp():
  var_now = datetime.datetime.now()
  var_timestamp = str(var_now.year) + str(var_now.month) + str(var_now.day) + "|" + str(var_now.hour) + ":" + str(var_now.minute) + ":" + str(var_now.second)
  return var_timestamp

def create_output_folder ():
    if not os.path.isdir(PATH_ROOT):
        log('The directory is not present. Creating a new one..')
        os.mkdir(PATH_ROOT)
    else:
        log('The directory is present.')
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
    try:
      opts, args = getopt.getopt(argv,"hlpi:s:c:",[])
    except getopt.GetoptError:
      log("The parameters and arguments aren't correct" + LOG_LVL["ERROR"])
      print(var_man_page)
      sys.exit(2)
    log("opts:" + str(opts))
    log("args:" + str(args))
    var_options = dict(opts)
    opt_keys = var_options.keys()
    if "-h" in opt_keys:
      print(var_man_page)
      sys.exit()
    if "-i" in opt_keys:
       global SESSION_ID
       SESSION_ID = var_options["-i"]
    elif "-s" in opt_keys:
        try:
            var_session_file = json.load(open(var_options["-s"]))
        except:
            var_session_file = {}
            var_file = open(var_options["-s"])
            var_session_file["sid"] = var_file.read().split("\"")[3]
        SESSION_ID = var_session_file["sid"]
        log("session-id loaded from session file: " + SESSION_ID)
    # Create directories for Logs and Output Files
    create_output_folder()
    log("delete_old_log_file")
    clear_log()
    if "-l" in opt_keys:
        load_local()
    elif "-p" in opt_keys:
        pull_all()
    if len(args) > 0:
        if args[0] in COMMANDS:
            command = args.pop(0)
            log("function:" + str(command))
            log("params:" + str(args))
            result = globals()[str(command)](args)
            print(result)
      #except BaseException as err:
        #log(str("FATAL ERROR: " + str(err)), LOG_LVL["FATAL"])
        #log("The Script crashed pls check manpage with -h option",
        #    LOG_LVL["FATAL"])
        #sys.exit(2)

if __name__ == "__main__":
  main(sys.argv[1:])
