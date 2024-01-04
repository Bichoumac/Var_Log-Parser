import gzip
from colorama import Fore
import re
import datetime
from urllib.parse import unquote


class Log():
    def __init__(self):
        self.file_path = ""

    def parse(self, year=2023):
        # Input = file_path
        # Output = [{key=value, key2=value2}, {key=value3, key2=value4}]
        
        return []

    def parse_date(self, line, year=2023):
        # return epoch_time format log in syslog header.
        try:
            date = re.match("^(\w+\s+\d{1,2}\s\S+)", line).group(1)
            # Convert syslog time string to datetime object
            datetime_obj = datetime.datetime.strptime(str(year)+" "+date, '%Y %b %d %H:%M:%S')

            # Convert datetime object to epoch time
            epoch_time = datetime_obj.timestamp()

            return int(epoch_time)
        except Exception as e:
            # Log the error
            print(f"Error: {e} : ", line)
            return 0

    def parse_host(self, line):
        try:
            host = re.match("^\w+\s+\d{1,2}\s\S+\s+(\S+)\s", line).group(1)

            return host
        except Exception as e:
            # Log the error
            print(Fore.RED, f"Error: {e}", Fore.RESET, ":", line)
            return 0

    def parse_app(self, line):
        try:
            app = re.match("^\w+\s+\d{1,2}\s\S+\s+\S+\s([^:\[]+)", line).group(1)

            return app
        except Exception as e:
            # Log the error
            print(Fore.RED, f"Error: {e}", Fore.RESET, ":", line)
            return 0

    def read_log(self):
        logs = []
        if self.file_path.endswith(".gz"):
            print(Fore.BLUE, "[+] gz found:", Fore.RESET, self.file_path)
            with gzip.open(self.file_path, 'r') as file_uncomp :
                logs = [line[:-1].decode() for line in file_uncomp]
        else:
            print(Fore.CYAN, "[+] Raw file found:", Fore.RESET, self.file_path)
            with open(self.file_path, 'r') as f:
                lines = f.readlines()
                logs = [line[:-1] for line in lines]
        return logs


class LogSecure(Log):
    # Secure/auth/authpriv log format:
    # Aug  1 16:15:03 ip-10-0-22-33 sshd[4042932]: Disconnected from user ubuntu 194.206.23.33 port 10404
    # Aug  1 16:15:03 ip-10-0-22-33 sshd[4042932]: Received disconnect from 194.206.23.33 port 10404:11: disconnected by user
    # Jul 21 08:54:02 ip-10-0-22-33 sshd[3971655]: Invalid user forensic from 194.206.23.33 port 10402
    # Jul 21 08:54:03 ip-10-0-22-33 sshd[3971655]: Connection reset by invalid user forensic 194.206.23.33 port 10402 [preauth]
    # Aug  4 10:00:44 frsopslftpv01 sshd[47255]: Failed keyboard-interactive/pam for invalid user sftpnmppp from 10.11.8.65 port 36978 ssh2
    # Aug  4 10:03:16 frsopslftpv04 sshd[76823]: Failed password for invalid user admin from 81.17.22.114 port 57214 ssh2
    # Aug  4 10:14:38 blabla sshd[77027]: Failed password for root from 159.223.71.99 port 43674 ssh2
    # Aug  3 15:28:50 ip-10-0-22-33 sshd[4063407]: Received disconnect from 194.206.23.33 port 10407:11: disconnected by user
    # Aug  3 15:28:50 ip-10-0-22-33 sshd[4063407]: Disconnected from user ubuntu 194.206.23.33 port 10407
    # Aug  2 12:48:25 ip-10-0-22-33 sudo:     root : TTY=pts/0 ; PWD=/cur_dir ; USER=root ; COMMAND=ls
    # Aug  2 12:49:20 ip-10-0-22-33 sudo: pam_unix(sudo:session): session opened for user root by ubuntu(uid=0)
    # Aug  2 12:49:20 ip-10-0-22-33 sudo: pam_unix(sudo:session): session closed for user root
    # Jul 27 14:53:40 ip-10-0-22-33 sshd[4013565]: Accepted publickey for ubuntu from 194.206.23.33 port 10401 ssh2: RSA SHA256:bFow9mZ6fRiqA5nnu0SpbFVk+zAM3gDjEfT/Cb17Tsg
    # Aug  4 10:07:03 blabla sshd[70427]: Accepted keyboard-interactive/pam for splunk from 10.11.10.25 port 54396 ssh2
    # Aug  4 10:07:01 blabla sshd[70367]: Accepted password for fexr from 10.11.13.49 port 59167 ssh2
    # Jul 21 15:42:24 ip-10-0-22-33 groupadd[3975171]: group added to /etc/gshadow: name=himds
    # Jul 21 15:42:24 ip-10-0-22-33 groupadd[3975171]: new group: name=himds, GID=998
    # Jul 21 15:42:24 ip-10-0-22-33 useradd[3975179]: new user: name=himds, UID=996, GID=998, home=/home/himds, shell=/bin/false, from=none

    # Aug  3 15:44:58 ip-10-0-22-33 sshd[4063637]: AuthorizedKeysCommand /usr/share/ec2-instance-connect/eic_run_authorized_keys ubuntu SHA256:AwjEXnACbmC5L8l8cUHP6GY7CU0Ef6R+DQu3BWTqFmo failed, status 22
    # Aug  3 15:47:35 ip-10-0-22-33 sshd[4063699]: Connection closed by authenticating user ubuntu 194.206.23.33 port 10409 [preauth]


    def __init__(self, file_path, year):
        super().__init__()
        self.year = year
        self.file_path = file_path


    def parse(self):
        res = []
        logs = self.read_log()
        
        for log in logs:
            res_log = {}
            res_log["_time"] = self.parse_date(log, self.year)
            res_log["hostname"] = self.parse_host(log)
            res_log["app"] = self.parse_app(log)
            res_log["_raw"] = log

            if "nvalid user" in log:
                # Jul 21 08:54:02 ip-10-0-22-33 sshd[3971655]: Invalid user forensic from 194.206.23.33 port 10402
                # Jul 21 08:54:03 ip-10-0-22-33 sshd[3971655]: Connection reset by invalid user forensic 194.206.23.33 port 10402 [preauth]
                res_log["tag"] = ["authentication"]
                res_log["event_type"] = "authentication"
                res_log["event_outcome"] = "failure"
                try:
                    res_log["user"] = re.search("nvalid\suser\s(\w+)", log).group(1)
                    res_log["src_ip"] = re.search("\s(\S+)\sport", log).group(1)
                    res_log["src_port"] = re.search("\sport\s(\d+)", log).group(1)
                    res_log["failure_reason"] = "invalid_user"
                except Exception as e:
                    print(Fore.RED, f"Error: {e}", Fore.RESET, ":", log)
            elif "Received disconnect" in log or "Disconnected from" in log:
                # Aug  1 16:15:03 ip-10-0-22-33 sshd[4042932]: Disconnected from user ubuntu 194.206.23.33 port 10404
                # Aug  1 16:15:03 ip-10-0-22-33 sshd[4042932]: Received disconnect from 194.206.23.33 port 10404:11: disconnected by user
                res_log["event_type"] = "session_end"
                res_log["event_outcome"] = "success"
                try:
                    res_log["src_ip"] = re.search("\s(\S+)\sport", log).group(1)
                    res_log["src_port"] = re.search("\sport\s(\d+)", log).group(1)
                    res_log["failure_reason"] = "invalid_user"
                    user = re.search("Disconnected\sfrom\suser\s(\S+)", log)
                    if user is not None:
                        res_log["user"] = user.group(1)
                except Exception as e:
                    print(Fore.RED, f"[-] Error - Parsing disconnect: {e}", Fore.RESET, ":", log)
            elif "PWD" in log or "COMMAND" in log:
                # Aug  2 12:48:25 ip-10-0-22-33 sudo:     root : TTY=pts/0 ; PWD=/cur_dir ; USER=root ; COMMAND=ls
                res_log["event_type"] = "session_opened_by_process"
                res_log["event_outcome"] = "success"
                try:
                    res_log["current_directory"] = re.search("PWD=(\S+)\s", log).group(1)
                    res_log["user"] = re.search("USER=(\S+)\s", log).group(1)
                    res_log["command_line"] = re.search("COMMAND=(.*)", log).group(1)
                except Exception as e:
                    print(Fore.RED, f"[-] Error - Parsing COMMAND: {e}", Fore.RESET, ":", log)
            elif "session opened" in log:
                # Aug  2 12:49:20 ip-10-0-22-33 sudo: pam_unix(sudo:session): session opened for user root by ubuntu(uid=0)
                res_log["tag"] = ["authentication"]
                res_log["event_type"] = "session_opened"
                res_log["event_outcome"] = "success"
                try:
                    res_log["dest_user"] = re.search("for\suser\s\S+\sby\s(\S+)", log).group(1)
                    res_log["src_user"] = re.search("for\suser\s(\S+)", log).group(1)
                except Exception as e:
                    print(Fore.RED, f"[-] Error - Parsing session opened: {e}", Fore.RESET, ":", log)
            elif "session closed" in log:
                # Aug  2 12:49:20 ip-10-0-22-33 sudo: pam_unix(sudo:session): session closed for user root
                res_log["event_type"] = "session_closed"
                res_log["event_outcome"] = "success"
                try:
                    res_log["user"] = re.search("for\suser\s(\S+)", log).group(1)
                except Exception as e:
                    print(Fore.RED, f"[-] Error - Parsing session closed: {e}", Fore.RESET, ":", log)
            elif "Failed" in log and "port" in log and "from" in log and "for" in log:
                # Aug  4 10:14:38 blabla sshd[77027]: Failed password for root from 159.223.71.99 port 43674 ssh2
                res_log["tag"] = ["authentication"]
                res_log["event_type"] = "authentication"
                res_log["event_outcome"] = "failure"
                try:
                    res_log["user"] = re.search("for\s(\S+)", log).group(1)
                    res_log["src_ip"] = re.search("\s(\S+)\sport", log).group(1)
                    res_log["src_port"] = re.search("\sport\s(\d+)", log).group(1)
                    res_log["failure_reason"] = "failed_credentials"
                except Exception as e:
                    print(Fore.RED, f"[-] Error - Parsing failed authent: {e}", Fore.RESET, ":", log)
            elif "Accepted" in log and "port" in log and "from" in log and "for" in log:
                # Jul 27 14:53:40 ip-10-0-22-33 sshd[4013565]: Accepted publickey for ubuntu from 194.206.23.33 port 10401 ssh2: RSA SHA256:bFow9mZ6fRiqA5nnu0SpbFVk+zAM3gDjEfT/Cb17Tsg
                # Aug  4 10:07:03 blabla sshd[70427]: Accepted keyboard-interactive/pam for splunk from 10.11.10.25 port 54396 ssh2
                # Aug  4 10:07:01 blabla sshd[70367]: Accepted password for fexr from 10.11.13.49 port 59167 ssh2
                res_log["tag"] = ["authentication"]
                res_log["event_type"] = "authentication"
                res_log["event_outcome"] = "success"
                try:
                    res_log["user"] = re.search("for\s(\S+)", log).group(1)
                    res_log["src_ip"] = re.search("\s(\S+)\sport", log).group(1)
                    res_log["src_port"] = re.search("\sport\s(\d+)", log).group(1)
                    res_log["auth_method"] = re.search("Accepted\s(\S+)\s", log).group(1)
                    if "publickey" in log:
                        res_log["publickey"] = re.search("ssh2:\s(.+)", log).group(1)
                except Exception as e:
                    print(Fore.RED, f"[-] Error - Parsing Accepted authent: {e}", Fore.RESET, ":", log)
            elif "groupadd" in res_log["app"]:
                if "new group" in log:
                # Jul 21 15:42:24 ip-10-0-22-33 groupadd[3975171]: new group: name=himds, GID=998
                    res_log["tag"] = ["group"]
                    res_log["event_type"] = "group_creation"
                    res_log["event_outcome"] = "success"
                    try:
                        res_log["group_name"] = re.search("name=([^,]+),", log).group(1)
                        res_log["gid"] = re.search("GID=(\d+)", log).group(1)
                    except Exception as e:
                        print(Fore.RED, f"[-] Error - Parsing groupadd: {e}", Fore.RESET, ":", log)
            elif "useradd" in res_log["app"]:
                # Jul 21 15:42:24 ip-10-0-22-33 useradd[3975179]: new user: name=himds, UID=996, GID=998, home=/home/himds, shell=/bin/false, from=none
                if "new user" in log:
                    res_log["tag"] = ["user_creation"]
                    res_log["event_type"] = "user_creation"
                    res_log["event_outcome"] = "success"
                    try:
                        res_log["user"] = re.search("name=([^,]+),", log).group(1)
                        res_log["gid"] = re.search("GID=(\d+)", log).group(1)
                        res_log["uid"] = re.search("UID=(\d+)", log).group(1)
                        res_log["home_dir"] = re.search("home=([^,]+)", log).group(1)
                        res_log["shell"] = re.search("shell=([^,]+)", log).group(1)
                    except Exception as e:
                        print(Fore.RED, f"[-] Error - Parsing useradd: {e}", Fore.RESET, ":", log)
            elif "Connection closed" in log:
                # Aug  3 15:47:35 ip-10-0-22-33 sshd[4063699]: Connection closed by authenticating user ubuntu 194.206.23.33 port 10409 [preauth]
                res_log["event_type"] = "session_closed"
                res_log["event_outcome"] = "success"
                try:
                    user = re.search("user\s(\S+)\s", log)
                    if user is not None:
                        res_log["user"] = user.group(1)
                    res_log["src_ip"] = re.search("\s(\S+)\sport", log).group(1)
                    res_log["src_port"] = re.search("port\s(\d+)", log).group(1)
                except Exception as e:
                    print(Fore.RED, f"[-] Error - Parsing Connection closed: {e}", Fore.RESET, ":", log)

            #print(res_log)
            res.append(res_log)
            
        return res


class LogCron (Log):
    # Jun  5 11:01:01 slnxvmgennedqual01 run-parts(/etc/cron.hourly)[23109]: starting mcelog.cron
    # Jun  5 11:01:01 slnxvmgennedqual01 run-parts(/etc/cron.hourly)[23124]: finished mcelog.cron
    # Jun  5 11:10:01 slnxvmgennedqual01 CROND[23328]: (root) CMD (/usr/lib64/sa/sa1 1 1)
    # Jun  4 03:28:01 slnxvmgennedqual01 anacron[8687]: Job `cron.daily' started
    # Jun  2 03:25:02 slnxvmgennedqual01 anacron[13878]: Job `cron.daily' terminated (produced output)
    # Jun  4 02:17:14 slnxvmgennedqual01 crontab[7777]: (root) LIST (XX)
    # Jun  4 00:01:01 slnxvmgennedqual01 anacron[6333]: Anacron started on 2023-06-04

    def __init__(self, file_path, year):
        super().__init__()
        self.year = year
        self.file_path = file_path


    def parse(self):
        res = []
        logs = self.read_log()
        
        for log in logs:
            res_log = {}
            res_log["_time"] = self.parse_date(log, self.year)
            res_log["hostname"] = self.parse_host(log)
            res_log["app"] = self.parse_app(log)
            res_log["_raw"] = log

            if "starting" in log:
                # Jun  5 11:01:01 slnxvmgennedqual01 run-parts(/etc/cron.hourly)[23109]: starting mcelog.cron
                res_log["tag"] = ["cron", "starting"]
                res_log["event_type"] = "starting_cron"
                try:
                    res_log["cron_name"] = re.search("starting\s(.*)", log).group(1)
                except Exception as e:
                    print(Fore.RED, f"Error starting cron: {e}", Fore.RESET, ":", log)
            elif "finished" in log:
                # Jun  5 11:01:01 slnxvmgennedqual01 run-parts(/etc/cron.hourly)[23124]: finished mcelog.cron
                res_log["tag"] = ["cron", "finished"]
                res_log["event_type"] = "finished_cron"
                try:
                    res_log["cron_name"] = re.search("finished\s(.*)", log).group(1)
                except Exception as e:
                    print(Fore.RED, f"Error: finished cron {e}", Fore.RESET, ":", log)
            elif "CMD" in log and "CRON" in res_log["app"]:
                # Jun  5 11:10:01 slnxvmgennedqual01 CROND[23328]: (root) CMD (/usr/lib64/sa/sa1 1 1)
                res_log["tag"] = ["cron", "execution", "process_creation"]
                res_log["event_type"] = "cron_process_creation"
                try:
                    res_log["user"] = re.search(":\s\(([^\)]*)\)", log).group(1)
                    res_log["command_line"] = re.search("CMD\s\((.*)\)", log).group(1)
                except Exception as e:
                    print(Fore.RED, f"Error: cron CMD {e}", Fore.RESET, ":", log)
            elif "Job" in log and ("started" in log or "terminated" in log):
                # Jun  4 03:28:01 slnxvmgennedqual01 anacron[8687]: Job `cron.daily' started
                # Jun  2 03:25:02 slnxvmgennedqual01 anacron[13878]: Job `cron.daily' terminated (produced output)
                res_log["status"] = "started" if "started" in log else "terminated"
                res_log["tag"] = ["cron", "execution", "job", res_log["status"]]
                res_log["event_type"] = "job_"+res_log["status"]
                try:
                    res_log["job_name"] = re.search("Job\s\`([^\']+)'", log).group(1)
                except Exception as e:
                    print(Fore.RED, f"Error: job started/terminated {e}", Fore.RESET, ":", log)
            elif "LIST" in log:
                # Jun  4 02:17:14 slnxvmgennedqual01 crontab[7777]: (root) LIST (XX)
                res_log["status"] = "started" if "started" in log else "terminated"
                res_log["tag"] = ["cron", "job", "discovery"]
                res_log["event_type"] = "list_cron"
                
                try:
                    res_log["service_related"] = re.search("LIST\s\(([^\)]*)\)", log).group(1)
                    res_log["user"] = re.search("\(([^\)]*)\)\sLIST", log).group(1)
                except Exception as e:
                    print(Fore.RED, f"Error: list_cron {e}", Fore.RESET, ":", log)

            res.append(res_log)
        return res


class LogApache(Log):
    # 10.6.200.70 - - [05/Jun/2023:08:24:05 +0200] "GET /consultercomptenominatif/management/health HTTP/1.1" 200 15 "-" "Java-SDK"
    # 10.6.200.70 - - [05/Jun/2023:08:24:05 +0200] "GET /consulterecrou/management/health HTTP/1.1" 200 15 "-" "Java-SDK"
    # 10.6.200.70 - - [05/Jun/2023:08:24:05 +0200] "GET /consulterparloir/management/health HTTP/1.1" 200 15 "-" "Java-SDK"
    # 10.6.200.84 - - [05/Jun/2023:08:24:05 +0200] "GET /consultertopographie/management/health HTTP/1.1" 200 15 "-" "Java-SDK"
    # 10.6.200.84 - - [05/Jun/2023:08:24:05 +0200] "GET /consulterecrou/management/health HTTP/1.1" 200 15 "-" "Java-SDK"
    # 10.6.200.84 - - [05/Jun/2023:08:24:05 +0200] "GET /consultertopographie/management/health HTTP/1.1" 200 15 "-" "Java-SDK"
    # 10.6.200.84 - - [05/Jun/2023:08:24:05 +0200] "GET /consultercantine/management/health HTTP/1.1" 200 15 "-" "Java-SDK"
    def __init__(self, file_path):
        super().__init__()
        self.file_path = file_path


    def parse(self):
        res = []
        logs = self.read_log()
        regexp = '^(?P<src_ip>\S+)\s(\S+)\s(?P<user>\S+)\s\[(?P<time>[^\]]+)\]\s\"(?P<http_method>\S+)\s(?P<uri>\S+)\s(?P<http_version>\S+)\"\s(?P<http_status_code>\d+)\s(?P<bytes>\S+)\s(?P<http_referrer>\S*?)\s\"(?P<user_agent>.*)\"'
        regexp_40x = '^(?P<src_ip>\S+)\s(\S+)\s(?P<user>\S+)\s\[(?P<time>[^\]]+)\]\s\"(?P<http_thing>\S*?)\"\s(?P<http_status_code>\d+)\s(?P<bytes>\S+)\s(?P<http_referrer>\S*?)\s\"(?P<user_agent>.*)\"'

        for log in logs:
            res_log = {}
            try:
                matched = re.match(regexp, log)
                if matched is None:
                    matched = re.match(regexp_40x, log)
                res_log = matched.groupdict()
                res_log["_time"] = int(datetime.datetime.strptime(res_log["time"], "%d/%b/%Y:%H:%M:%S %z").timestamp())
            except Exception as e:
                print(Fore.RED, f"[-] Error - Parsing Access log: {e}", Fore.RESET, ":", log)

            res_log["_raw"] = log
            res.append(res_log)

        return res

class LogSyslog(Log):
    # List services:
    # parsed:
    # slazsivssapp01 CRON
    # slazsivssapp01 apparmor.systemd
    # slazsivssapp01 containerd
    # slazsivssapp01 dockerd

    # Not interesting
    # slazsivssapp01 KVP
    # slazsivssapp01 apachectl
    # slazsivssapp01 chronyd
    # slazsivssapp01 cloud-ifupdown-helper
    # slazsivssapp01 cloud-init
    # slazsivssapp01 cron
    # slazsivssapp01 crontab
    # slazsivssapp01 dbus-daemon
    # slazsivssapp01 dhclient
    # slazsivssapp01 ifup
    # slazsivssapp01 kernel
    # slazsivssapp01 mount
    # slazsivssapp01 omiserver
    # slazsivssapp01 sh
    # slazsivssapp01 shutdown.sh
    # slazsivssapp01 snapd
    # slazsivssapp01 startup.sh
    # slazsivssapp01 systemd
    # slazsivssapp01 systemd-fsck
    # slazsivssapp01 rsyslogd
    # slazsivssapp01 systemd-growfs
    # slazsivssapp01 systemd-udevd
    # slazsivssapp01 waagent


    def __init__(self, file_path, year):
        super().__init__()
        self.year = year
        self.file_path = file_path


    def parse(self):
        res = []
        logs = self.read_log()
        
        for log in logs:
            res_log = {}
            res_log["_time"] = self.parse_date(log, self.year)
            res_log["hostname"] = self.parse_host(log)
            res_log["_raw"] = log
            res_log["app"] = self.parse_app(log)

            if res_log["app"] == "CRON":
                if "starting" in log:
                    # Jun  5 11:01:01 slnxvmgennedqual01 run-parts(/etc/cron.hourly)[23109]: starting mcelog.cron
                    res_log["tag"] = ["cron", "starting"]
                    res_log["event_type"] = "starting_cron"
                    try:
                        res_log["cron_name"] = re.search("starting\s(.*)", log).group(1)
                    except Exception as e:
                        print(Fore.RED, f"Error starting cron: {e}", Fore.RESET, ":", log)
                elif "finished" in log:
                    # Jun  5 11:01:01 slnxvmgennedqual01 run-parts(/etc/cron.hourly)[23124]: finished mcelog.cron
                    res_log["tag"] = ["cron", "finished"]
                    res_log["event_type"] = "finished_cron"
                    try:
                        res_log["cron_name"] = re.search("finished\s(.*)", log).group(1)
                    except Exception as e:
                        print(Fore.RED, f"Error: finished cron {e}", Fore.RESET, ":", log)
                elif "CMD" in log and "CRON" in res_log["app"]:
                    # Jun  5 11:10:01 slnxvmgennedqual01 CROND[23328]: (root) CMD (/usr/lib64/sa/sa1 1 1)
                    res_log["tag"] = ["cron", "execution", "process_creation"]
                    res_log["event_type"] = "cron_process_creation"
                    try:
                        res_log["user"] = re.search(":\s\(([^\)]*)\)", log).group(1)
                        res_log["command_line"] = re.search("CMD\s\((.*)\)", log).group(1)
                    except Exception as e:
                        print(Fore.RED, f"Error: cron CMD {e}", Fore.RESET, ":", log)
                elif "Job" in log and ("started" in log or "terminated" in log):
                    # Jun  4 03:28:01 slnxvmgennedqual01 anacron[8687]: Job `cron.daily' started
                    # Jun  2 03:25:02 slnxvmgennedqual01 anacron[13878]: Job `cron.daily' terminated (produced output)
                    res_log["status"] = "started" if "started" in log else "terminated"
                    res_log["tag"] = ["cron", "execution", "job", res_log["status"]]
                    res_log["event_type"] = "job_"+res_log["status"]
                    try:
                        res_log["job_name"] = re.search("Job\s\`([^\']+)'", log).group(1)
                    except Exception as e:
                        print(Fore.RED, f"Error: job started/terminated {e}", Fore.RESET, ":", log)
            elif res_log["app"] == "apparmer.systemd":
                if "Restarting" in log:
                    res_log["event_type"] = "restarting_apparmor"
                if "Reloading" in log:
                    res_log["event_type"] = "reloading_apparmor_profiles"
            elif res_log["app"] in ["containerd", "dockerd"]:
                matches = re.findall(r"(\w+)\s*=\s*(?:\"(.*?)(?<!\\)\"|(\S+))", log)
                parsed_log = {key:value if len(value)!=0 else no_space for (key, value, no_space) in matches}
                res_log.update(parsed_log)


            res.append(res_log)
        return res

class LogAudit(Log):
    # type=PROCTITLE msg=audit(1691482917.193:2236144): proctitle=706F7374677265733A206865616C74685F7374617475735F776F726B657220
    # type=CRED_REFR msg=audit(1685521501.683:1219995): pid=8405 uid=0 auid=994 ses=119329 msg='op=PAM:setcred grantors=pam_env,pam_unix acct="pcp" exe="/usr/sbin/crond" hostname=? addr=? terminal=cron res=success' 
    # type=CRED_DISP msg=audit(1685521501.744:1219996): pid=8405 uid=0 auid=994 ses=119329 msg='op=PAM:setcred grantors=pam_env,pam_unix acct="pcp" exe="/usr/sbin/crond" hostname=? addr=? terminal=cron res=success'
    # type=USER_END msg=audit(1685521501.746:1219997): pid=8405 uid=0 auid=994 ses=119329 msg='op=PAM:session_close grantors=pam_loginuid,pam_keyinit,pam_limits,pam_systemd acct="pcp" exe="/usr/sbin/crond" hostname=? addr=? terminal=cron res=success'
    # type=USER_ACCT msg=audit(1685521681.751:1219998): pid=8493 uid=0 auid=4294967295 ses=4294967295 msg='op=PAM:accounting grantors=pam_access,pam_unix,pam_localuser acct="pcp" exe="/usr/sbin/crond" hostname=? addr=? terminal=cron res=success'
    # type=LOGIN msg=audit(1685248801.659:1207723): pid=17266 uid=0 old-auid=4294967295 auid=0 tty=(none) old-ses=4294967295 ses=118276 res=1 

    def __init__(self, file_path):
        super().__init__()
        self.file_path = file_path

    def parse_date(self, log):
        date_res = ""
        try:
            date_res = re.search("msg=audit\((\d+)", log).group(1)
        except Exception as e:
            print(Fore.RED, f"[-] Error - AuditD fail parse_date", Fore.RESET, ":", log)
        return date_res

    def convert_commandline(self, hex_value):
        # Take an hex value in 706F7374677265733A206865616C74685F7374617475735F776F726B657220
        hex_value = re.sub("([a-fA-F0-9]{2})", "%\\1", hex_value)
        return unquote(hex_value)

    def parse(self):
        res = []
        logs = self.read_log()

        for log in logs:
            res_log = {}
            res_log["_time"] = self.parse_date(log)
            res_log["_raw"] = log
            res_log["tag"] = []

            pattern = r'\b(\w+)=([\S]+)'
            try:
                matches = re.findall(pattern, log)
                tmp_keyvalue = {key : value.strip("\"").strip("\'") for key, value in matches}
                res_log.update(tmp_keyvalue)

                if "cmd" in res_log.keys():
                    res_log["cmd"] = self.convert_commandline(res_log["cmd"])
                    res_log["command_line"] = res_log["cmd"]

                if "proctitle" in res_log.keys():
                    res_log["proctitle"] = self.convert_commandline(res_log["proctitle"])
                    res_log["command_line"] = res_log["proctitle"]
                
                if res_log["type"] in ["BPRM_FCAPS", "CAPSET", "CWD", "EXECVE", "OBJ_PID", "PATH", "PROCTITLE", "SECCOMP", "SYSCALL", "USER_CMD"]:
                    res_log["tag"].append("process")
                if res_log["type"] in ["PATH"]:
                    res_log["tag"].append("file_access")
                if res_log["type"] in ["SERVICE_START", "SERVICE_STOP", "SYSTEM_BOOT", "SYSTEM_RUNLEVEL", "SYSTEM_SHUTDOWN"]:
                    res_log["tag"].append("service")

                if res_log["type"] in ["GRP_MGMT", "GRP_CHAUTHTOK", "ADD_GROUP", "DEL_GROUP"]:
                    res_log["tag"].append("group_management")
                if res_log["type"] in ["ADD_USER", "DEL_USER", "USER_MGMT", "USER_CHAUTHTOK"]:
                    res_log["tag"].append("user_management")
                if res_log["type"] in ["LOGIN", "USER_CMD", "GRP_AUTH", "CHUSER_ID", "CHGRP_ID", "USER_LOGIN", "USER_LOGOUT", "USER_ERR", "USER_ACCT", "ACCT_LOCK", "ACCT_UNLOCK", "USER_START", "USER_END", "CRED_ACQ", "CRED_REFR", "CRED_DISP"]:
                    res_log["tag"].append("authentication")
                if res_log["type"] in ["KERNEL", "CONFIG_CHANGE", "DAEMON_ABORT", "DAEMON_ACCEPT", "DAEMON_CLOSE", "DAEMON_CONFIG", "DAEMON_END", "DAEMON_ERR", "DAEMON_RESUME", "DAEMON_ROTATE", "DAEMON_START", "FEATURE_CHANGE"] :
                    res_log["tag"].append("auditd_tampering")

            except Exception as e:
                print(Fore.RED, f"[-] Error - AuditD fail parse {e}", Fore.RESET, ":", log)              

            res.append(res_log)

        return res

class LogAptHistory(Log):
    # Start-Date: 2023-05-03  10:18:06
    # Commandline: /usr/bin/unattended-upgrade
    # Upgrade: libxml2:amd64 (2.9.4+dfsg1-7+deb10u5, 2.9.4+dfsg1-7+deb10u6)
    # End-Date: 2023-05-03  10:18:07
    # 
    # Start-Date: 2023-05-10  18:05:28
    # Commandline: apt-get -y --only-upgrade true install containerd.io=1.6.21-1
    # Requested-By: nxautomation (995)
    # Upgrade: containerd.io:amd64 (1.6.20-1, 1.6.21-1)
    # End-Date: 2023-05-10  18:05:37

    def __init__(self, file_path):
        super().__init__()
        self.file_path = file_path


    def read_log(self):
        logs = super().read_log()

        # print(logs)
        # Define a delimiter for replacing the empty line

        delim = "-+-+-"
        
        for k in range(len(logs)):
            if len(logs[k])==0:
                logs[k] = delim
        
        logs = [log for log in ("\n".join(logs)).split(delim+"\n") if len(log) != 0]
        
        return logs

    def parse_date(self, log):
        date_res = ""
        try:
            date_res = re.search("Start-Date:\s(.*?)\n", log).group(1)
            format_string = "%Y-%m-%d  %H:%M:%S"
            datetime_object = datetime.datetime.strptime(date_res, format_string)
            epoch_timestamp = datetime_object.timestamp()
            return int(epoch_timestamp)

        except Exception as e:
            print(Fore.RED, f"[-] Error - AptHistory parse_date {e}", Fore.RESET, ": {", log, "}")
            return 0

    def parse(self):
        res = []
        logs = self.read_log()

        for log in logs:
            res_log = {}
            res_log["_time"] = self.parse_date(log)
            res_log["_raw"] = log
            
            command_line = re.search("Commandline:\s(.*?)\n", log)
            start_time = re.search("Start-Date:\s(.*?)\n", log)
            end_time = re.search("End-Date:\s(.*?)\n", log)
            user = re.search("Requested-By:\s(\S+?)\n", log)
            installed_package = re.search("Install:\s(.+?)\n", log)
            upgraded_package = re.search("Upgrade:\s(.+?)\n", log)

            if command_line is not None:
                res_log["command_line"] = command_line.group(1)
            if start_time is not None:
                res_log["start_time"] = start_time.group(1)
                res_log["start_time"] = epoch_timestamp = int(datetime.datetime.strptime(res_log["start_time"], "%Y-%m-%d  %H:%M:%S").timestamp())
            if end_time is not None:
                res_log["end_time"] = end_time.group(1)
                res_log["end_time"] = epoch_timestamp = int(datetime.datetime.strptime(res_log["end_time"], "%Y-%m-%d  %H:%M:%S").timestamp())
            if user is not None:
                res_log["user"] = user.group(1)
            if installed_package is not None:
                res_log["package_name"] = installed_package.group(1)
                res_log["event_type"] = "package_install"
            if upgraded_package is not None:
                res_log["package_name"] = upgraded_package.group(1)
                res_log["event_type"] = "package_upgrade"
            if "package_name" in res_log.keys():
                res_log["package_name"] = re.split(r',(?![^(]*\))', res_log["package_name"])

            res.append(res_log)
        return res

class LogMail (Log):
    # Aug  9 11:33:04 slnmessagerielol postfix/qmgr[11164]: 5169E419: from=<jira@contosoonline.com>, size=18827, nrcpt=1 (queue active)
    # Aug  9 11:33:04 slnmessagerielol postfix/qmgr[11164]: D46EBA7E: removed
    # May 15 02:00:01 slnxvmgennedqual01 postfix/qmgr[1553]: CF992131D: removed
    # May 15 02:00:01 slnxvmgennedqual01 postfix/qmgr[1553]: DDCBD497: from=<ned@slnxvmgennedqual01.z-ptx-44.fr.sopra>, size=1011, nrcpt=1 (queue active)
    # May 15 02:00:01 slnxvmgennedqual01 postfix/local[17942]: CF992131D: to=<ned@slnxvmgennedqual01.z-ptx-44.fr.sopra>, orig_to=<ned>, relay=local, delay=0.16, delays=0.12/0.03/0/0.02, dsn=2.0.0, status=sent (delivered to mailbox)
    # May 15 02:00:01 slnxvmgennedqual01 postfix/pickup[17807]: E2B511254: uid=1002 from=<ned>
    # May 15 02:00:01 slnxvmgennedqual01 postfix/cleanup[17931]: E163E1255: message-id=<20230515000001.E163E1255@slnxvmgennedqual01.z-ptx-44.fr.sopra>
    # Aug  9 11:33:04 slnmessagerielol postfix/smtp[124664]: D46EBA7E: to=<test.user@contoso.com>, relay=contoso-com.mail.protection.outlook.com[52.101.68.36]:25, delay=0.72, delays=0.09/0.01/0.16/0.46, dsn=2.6.0, status=sent (250 2.6.0 <JIRA.938152.1690810170000.3399613.1691573583862@Atlassian.JIRA> [InternalId=105849469029151, Hostname=AS8PR07MB7669.eurprd07.prod.outlook.com] 29353 bytes in 0.060, 472.320 KB/sec Queued mail for delivery)
    # Aug  9 11:33:04 slnmessagerielol postfix/smtp[122289]: 5169E419: enabling PIX workarounds: delay_dotcrlf for contoso-com.mail.protection.outlook.com[52.101.68.16]:25
    # Aug  9 11:33:04 slnmessagerielol postfix/smtpd[123873]: lost connection after RSET from unknown[10.4.3.148]
    # Aug  9 11:33:04 slnmessagerielol postfix/smtpd[123792]: NOQUEUE: reject: RCPT from unknown[10.4.129.201]: 550 5.1.1 <lol@contosoonline.com>: Recipient address rejected: User unknown in local recipient table; from=<lol@contosoonline.com> to=<lol@contosoonline.com> proto=SMTP helo=<lolserverlol.contosoonline.com>
    # Aug  9 11:33:04 slnmessagerielol postfix/smtpd[123792]: connect from unknown[10.4.129.201]
    # Aug  9 11:33:04 slnmessagerielol postfix/smtpd[121961]: disconnect from unknown[10.4.2.17]
    # Aug  9 11:33:04 slnmessagerielol opendkim[4646]: 5169E419: DKIM-Signature field added (s=20210623, d=contosoonline.com)
    def __init__(self, file_path, year):
        super().__init__()
        self.year = year
        self.file_path = file_path


    def parse(self):
        res = []
        logs = self.read_log()
        
        for log in logs:
            res_log = {}
            res_log["_time"] = self.parse_date(log, self.year)
            res_log["_raw"] = log

            src_mail_address = re.search("from=\<([^\>]*)\>", log)
            if src_mail_address is not None:
                res_log["src_mail"] = src_mail_address.group(1)

            dest_mail_address = re.search("to=\<([^\>]*)\>", log)
            if dest_mail_address is not None:
                res_log["dest_mail"] = dest_mail_address.group(1)
            
            subject = re.search("(?<=Subject: ).*?(?=\sfrom)", log)
            if subject is not None:
                res_log["subject"] = subject.group(0)

            message_id = re.search("^\S+\s+\d+\s\d+:\d+:\d+\s\S+\s\S+\s([A-Z0-9]+):", log)
            if message_id is not None:
                res_log["message_id"] = message_id.group(1)

            # print(res_log)
            res.append(res_log)
        return res

class LogDpkg (Log):
    # 2023-06-13 14:00:47 status half-installed libssl1.1:amd64 1.1.1n-0+deb10u4
    # 2023-06-13 14:00:48 status installed libssl1.1:amd64 1.1.1n-0+deb10u5
    # 2023-06-13 14:00:48 status unpacked libssl1.1:amd64 1.1.1n-0+deb10u5
    # 2023-06-20 08:12:12 status triggers-pending libc-bin:amd64 2.28-10+deb10u2
    # 2023-06-20 08:12:12 status half-configured libxpm4:amd64 1:3.5.12-1
    # 2023-06-13 14:00:48 configure libssl1.1:amd64 1.1.1n-0+deb10u5 <none>
    # 2023-06-13 14:00:48 trigproc libc-bin:amd64 2.28-10+deb10u2 <none>
    # 2023-06-19 09:21:26 upgrade python3-requests:all 2.21.0-1 2.21.0-1+deb10u1
    # 2023-06-13 14:00:48 startup packages configure
    # 2023-06-19 09:21:22 startup archives unpack

    def __init__(self, file_path):
        super().__init__()
        self.file_path = file_path

    def parse_date (self, log):
        res = re.search("^(\d+-\d+-\d+\s\d+:\d+:\d+)\s", log).group(1)
        format_string = "%Y-%m-%d %H:%M:%S"

        datetime_object = datetime.datetime.strptime(res, format_string)
        epoch_timestamp = datetime_object.timestamp()

        return epoch_timestamp

    def parse(self):
        res = []
        logs = self.read_log()
        
        for log in logs:
            res_log = {}
            res_log["_time"] = self.parse_date(log)
            res_log["_raw"] = log

            if "status half-installed" in log or "status installed" in log:
                package_name = re.search("installed\s(.*)$", log).group(1)
                res_log["package_name"] = package_name
                res_log["event_type"] = "package_install"
            elif "status half-configured" in log:
                package_name = re.search("half-configured\s(.*)$", log).group(1)
                res_log["package_name"] = package_name
                res_log["event_type"] = "package_configure"
            elif "upgrade" in log:
                package_name = re.search("upgrade\s(.*)$", log).group(1)
                res_log["package_name"] = package_name
                res_log["event_type"] = "package_upgrade"

            res.append(res_log)
        return res

class LogYum (Log):
    # Nov 04 09:51:14 Installed: setools-libs-3.3.8-4.el7.x86_64
    # Nov 04 09:51:14 Updated: libselinux-python-2.5-14.1.el7.x86_64

    def __init__(self, file_path, year):
        super().__init__()
        self.year = year
        self.file_path = file_path


    def parse(self):
        res = []
        logs = self.read_log()
        
        for log in logs:
            res_log = {}
            res_log["_time"] = self.parse_date(log, self.year)
            res_log["hostname"] = self.parse_host(log)
            res_log["_raw"] = log

            if "Installed" in log :
                package_name = re.search("Installed:\s(.*)$", log).group(1)
                res_log["package_name"] = package_name
                res_log["event_type"] = "package_install"
            elif "Updated" in log:
                package_name = re.search("Updated:\s(.*)$", log).group(1)
                res_log["package_name"] = package_name
                res_log["event_type"] = "package_update"

            res.append(res_log)
        return res