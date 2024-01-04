import re
import argparse
import os
import glob
from colorama import Fore
from parser_class import LogSecure, LogCron, LogApache, LogAudit, LogDpkg, LogYum, LogAptHistory, LogMail, LogSyslog
import json
import re
import pandas as pd
import datetime

DISPLAY_INFO = False

def dict_dump_to_jsonl(output_path, input_file, parsed_log, endpoint_name):
    # Input:
    # data = [
    #    {"key01":"value","key02":"value"},
    #    {"key11":"value","key12":"value"},
    #    {"key21":"value","key22":"value"}
    # ]

    # endpoint--var_log-input_file
    output_filename = re.search("\/([^\/]+)$", input_file).group(1)

    output_filepath = os.path.join(output_path, endpoint_name+"--var_log-"+output_filename)

    if DISPLAY_INFO:
        print(Fore.GREEN, "[INFO] Logs saved in {}".format(output_filepath), Fore.RESET)
    with open(output_filepath, 'w+') as fp:
        try :
            fp.write('\n'.join(json.dumps(i) for i in parsed_log))
        except Exception as e:
            print(Fore.RED + f"[Error] Exception in the dict_dump_to_jsonl function {e}", Fore.RESET)

def load_bodyfile(bodyfile_path):
    # Example of body file:
    # filename|inode|mode_as_string|uid|gid|size|atime|mtime|ctime|btime
    # "/var/opt/omi/omiauth"|528871|drwxr-xr-x|0|0|4096|1687331056|1665562995|1677857011|1677857011
    try:
        res = pd.read_csv(bodyfile_path, sep="|")
        return res
    except FileNotFoundError as filenotfound:
        print(Fore.RED, "[ERROR] Body file not found.. {}".format(filenotfound), Fore.RESET)
        return None

def search_year (bodyfile, filename):
    # Example of body file:
    # filename|inode|mode_as_string|uid|gid|size|atime|mtime|ctime|btime
    # "/var/opt/omi/omiauth"|528871|drwxr-xr-x|0|0|4096|1687331056|1665562995|1677857011|1677857011
    # In case the bodyfile doesn't have the filename, we search the same filename with ".gz" at the end.
    # In case there's still nothing, we search in the filename with the following format: YYYMMDD
    # In case there's still nothing, we return the current year date
    res = bodyfile[bodyfile["filename"].apply(lambda x: filename.endswith(x))].tail(1)
    if len(res) == 0:
        # The filename not found in body file
        res = bodyfile[bodyfile["filename"].apply(lambda x: f"{filename}.gz".endswith(x))].tail(1)
    if len(res) == 0:
        # The filename.gz not found in body file
        res = re.search("(\d{4})\d{2}\d{2}$", filename)
        if res is not None:
            # No YYYYMMDD found at the end of the filename
            return res.group(1)
        else:
            print(Fore.MAGENTA, f"[WARNING] No year found for file {filename}, current year returned")
            return datetime.datetime.now().year
    return datetime.datetime.fromtimestamp(int(res["mtime"])).year
    

def parse_log(input_path, output_path, log_type, endpoint_name, bodyfile_path):
    file_path = os.path.join(input_path, log_type)
    pattern = file_path+"*"
    list_file = glob.glob(pattern)

    if len(list_file)==0:
        if DISPLAY_INFO :
            print(Fore.YELLOW, "[INFO] No file following the pattern {} found".format(pattern), Fore.RESET)
        return

    log_class = ""

    bodyfile = load_bodyfile(bodyfile_path)

    for f in list_file:
        if log_type in ["secure", "auth", "authpriv"]:
            year = search_year(bodyfile, f)
            log_class = LogSecure(f, year)
        elif log_type in ["cron"]:
            year = search_year(bodyfile, f)
            log_class = LogCron(f, year)
        elif log_type in ["yum.log"]:
            year = search_year(bodyfile, f)
            log_class = LogYum(f, year)
        elif log_type in ["mail.log", "maillog"]:
            year = search_year(bodyfile, f)
            log_class = LogMail(f, year)
        elif log_type in ["syslog"]:
            year = search_year(bodyfile, f)
            log_class = LogSyslog(f, year)
        elif log_type in ["httpd/access", "apache2/access", "apache/access", "nginx/access", "tomcat/access"]:
            log_class = LogApache(f)
        elif log_type in ["audit/audit.log"]:
            log_class = LogAudit(f)
        elif log_type in ["dpkg.log"]:
            log_class = LogDpkg(f)
        elif log_type in ["apt/history.log"]:
            log_class = LogAptHistory(f)
        else:
            if DISPLAY_INFO :
                print(Fore.YELLOW, f"[INFO] Need to parse {log_type}", Fore.RESET)
            return ""

        parsed_log = log_class.parse()
        dict_dump_to_jsonl(output_path, f, parsed_log, endpoint_name)


def main(input_path, output_path, endpoint_name, bodyfile_path):
    list_logs = ["secure", "messages", "auth", "authpriv", "cron", 
                 "httpd/access", "apache2/access", "apache/access", "nginx/access", "tomcat/access", "audit/audit.log", 
                 "mail.log", "maillog", "boot.log", "syslog", "apt/history.log", "dpkg.log", "yum.log"]
    parsed_log = []
    for log_type in list_logs:
        parse_log(input_path, output_path, log_type, endpoint_name, bodyfile_path)



if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog='UAC Var Log Parser', description='Produce jsonl from var/log logs directory')

    parser.add_argument('--input_path', help="Absolute path to the var/log folder", required=True)
    parser.add_argument('--output_path', help="Absolute path to the output", required=True)
    parser.add_argument('--endpoint_name', help="Name of the endpoint", required=True)
    parser.add_argument('--display_info', help="display_info 0=False, 1=True", choices=[0, 1], type=int, default=1, required=False)

    args = parser.parse_args()
    var_log_path = args.input_path

    # Construct bodyfile path
    allFiles_path = var_log_path.split("/")[:-3]
    allFiles_path.append("bodyfile")
    allFiles_path.append("bodyfile.txt")
    bodyfile_path = "/".join(allFiles_path)

    output_path = args.output_path
    endpoint_name = args.endpoint_name
    DISPLAY_INFO = True if args.display_info==1 else False
    main(var_log_path, output_path, endpoint_name, bodyfile_path)

