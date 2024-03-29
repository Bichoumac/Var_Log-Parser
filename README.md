# Input

The input is the path to a /var/log folder.

# Output

The output is based on the output_path argument.
For each file that it parsed, it will produce a jsonl file in the $OUTPUT_PATH folder, named $filename$.jsonl

For example, if it parsed "/var/log/secure", it will produce $OUTPUT_PATH/secure.jsonl
# How to launch

```bash
python3 var_log_parser.py --input_path $PATH_TO_VAR_LOG --output_path $OUTPUT_PATH
```

# What does it parse : 
## Currently done
* secure
* messages
* auth
* authpriv
* cron
* httpd/access
* apache/access
* apache2/access
* nginx/access
* audit/audit.log
* dpkg.log
* yum.log
* apt/history.log
* mail.log / maillog
* syslog

## TODO 
* boot.log


# Comment
## Access logs parsing
Since the log format of access logs can be non standard, we've only parsed the "standard version" which is : 

```bash
src_ip user host [date] http_method uri, http_version http_status_code bytes http_referrer "user_agent"
```

## How it's done
There's one main class (Log), and the others are inherited class (Log*)

The class Log has the following functions :
* parse (parse the logs, and output a list of dict. Empty for the Log class, as there's no "standard" log format)
* parse_date (that parse the date on standard syslog)
* parse_app (that parse the app on secure logs)
* parse_host (that parse the host in standard syslog)

# Important note
Some logs doesn't have the year of the event.
It's especially annoying when we have logs from a year, and logs from another year.
The year detection is then based on multiple elements : 
1. First we are extracting the **mtime** in the the bodyfile that is generated using a UAC-Triage collector
2. If we don't find the .log file in the bodyfile, we search for the same file but compressed with a .gz
3. If there's nothing, then we search for in the following format in the filename : YYYYMDD
4. If there's still nothing, we put the current date year as the year
