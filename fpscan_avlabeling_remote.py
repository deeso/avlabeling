import sys, argparse, threading, json, shlex, time
import subprocess, traceback, os, sys, sqlite3
from basic_multi_host_commands import *

from datetime import datetime

def time_str():
    return str(datetime.now().strftime("%H:%M:%S.%f %m-%d-%Y"))


parser = argparse.ArgumentParser(description="Perform fpscan on remote Linux hosts with paramiko")
parser.add_argument('-user', help='user to log in with', type=str)
parser.add_argument('-password', help='user to log in with', type=str)
parser.add_argument('-hosts', help='hosts to connect to', nargs='*', type=str)
parser.add_argument('-malware_location', help='remote host directory with the malware (I mounted with NFS)', type=str)
parser.add_argument('-scan_location', help='Scan for the number of files so work is spread evenly', type=str)
parser.add_argument('-avlabel_location', help='base location of avlabeling code on system', type=str)
parser.add_argument('-total_files', help='Number of files so work is spread evenly', type=int)
parser.add_argument('-sqlite_location', help='Location of the sqlite_db', type=str)
parser.add_argument('-debug', help='dump raw logs from all the host in the current directory', action="store_true", default=False)

START_DATA_TERM = "=====START_DATA_DUMP====="
END_DATA_TERM = "=====END_DATA_DUMP====="
# print ("Started: %s"%stime.strftime("%H:%M:%S.%f %m-%d-%Y"))
# print ("Ended: %s"%etime.strftime("%H:%M:%S.%f %m-%d-%Y"))
COMPLETED_TERM = "=====COMPLETED====="
FPSCAN_AVLABEL_CMD = "python {avlabel_location}/fpscan_avlabeling_stdout.py {malware_location} {start} {end}"
def generate_command(avlabel_location, malware_location, start, end):
    cmd_dict = {'avlabel_location':avlabel_location, 'malware_location':malware_location, 'start':start, 'end':end}
    cmd = FPSCAN_AVLABEL_CMD.format(**cmd_dict)
    return cmd

def execute_remote_command(username, password, host, command, output_sqllite_db, debug=False):
    client = ssh_to_target(host, username=username, password=password)
    data = exec_cmds(client, password, [command, ])
    process = True
    _data = "".join(data)
    if debug:
        open("%s-debug.log"%host, 'a').write(_data)

    if _data.find(START_DATA_TERM) == -1:
        print ("[X] Host (%s) failed to get back data, no data start"%(host))
        process = False

    if _data.find(END_DATA_TERM) == -1:
        print ("[X] Host (%s) failed to get back data, no data end"%(host))
        process = False

    if process:
        raw_results = _data.split(START_DATA_TERM)[1].split(END_DATA_TERM)[0]
        try:
            # XXX This is pretty dangerous, evaluating the Python dictionary to get an object
            # json might be better
            #print raw_results
            hash_results = json.loads(raw_results)
            if len(hash_results) > 0:
                write_files_results(hash_results, output_sqllite_db, 'fpscan')
            else:
                print ("[X] Host (%s) failed to get back data, no JSON data"%(host))
                process = False
        except:
            print ("[X] Host (%s) failed to get back data, JSON data unparseable"%(host))
            process = False
    completed = "[=] Finished execution %s"%time_str()
    if _data.find(COMPLETED_TERM) > 0:
        completed = _data.split(END_DATA_TERM)[1].split(COMPLETED_TERM)[0] + "\n" + completed


    if process:
        print ("[+] Host (%s) successfully completed scan.\n%s"%(host, completed))
    else:
        print ("[X] Host (%s) failed to complete scan.\n%s"%(host, completed))


def write_files_results(hash_results, output_sqllite_db, av_engine='clamav'):
    conn = sqlite3.connect(output_sqllite_db)
    c = conn.cursor()
    rows = []
    for h,l_m in hash_results.items():
        l, m = l_m
        rows.append((h,l, m, av_engine))
    print ("[=] %s Inserted %d results into db: %s."%(time_str(), len(rows), output_sqllite_db))
    c.executemany("INSERT INTO hash_labels VALUES (?,?,?,?)", rows)
    conn.commit()


def init_database(output_sqllite_db):
    conn = sqlite3.connect(output_sqllite_db)
    c = conn.cursor()
    c.execute('''CREATE TABLE hash_labels (hash, label, meta, av_engine)''')
    c.close()
    conn.commit()


LABEL_SEP = '] <'
VIRUS_SHARE_HASH = "VirusShare_"
def post_process_data(raw_results, malware_location=None):
    results = [i.strip() for i in raw_results.splitlines() if i.find('[') == 0]
    hash_results = {}
    for line in lines:
        if line.find(LABEL_SEP) == -1:
            print ("[X] Line does not contain a LABEL_SEP separator: %s"%line)
            continue
        label = line.splitlines(LABEL_SEP)[1].split()[0]
        label.strip().strip('>')

        h = line.split('VirusShare_')[1][:32]
        if f.find(VIRUS_SHARE_HASH) == -1:
            print ("[X] File entry does not contain a VIRUS_SHARE separator: %s"%f)
            continue

        hash_results[h] = (label, line.strip())
    return hash_results



def perform_fp_scan_hosts(username, password, host_list, commands, output_sqllite_db, debug=False):
    threads = []
    pos = 0
    while pos < len(commands):
        command = commands[pos]
        host = host_list[pos%len(host_list)]
        t = threading.Thread(target=execute_remote_command, args=(username, password, host, command, output_sqllite_db, debug))
        print ("[=] %s Started Host (%s) command: %s"%(time_str(), host, command))
        t.start()
        threads.append(t)
        # Give thread time to login and start working before starting next onw
        time.sleep(10)
        pos += 1

    print ("[=] %s All commands started waiting for the threads to complete."%(time_str()))
    for t in threads:
        t.join()


if __name__ == '__main__':
    args = parser.parse_args()
    stime = datetime.now()

    if args.user is None or args.password is None:
        print ("[X] Must provide user name and password")
        sys.exit(1)

    if args.hosts is None or len(args.hosts) == 0:
        print ("[X] Must provide hosts")
        sys.exit(1)

    if args.malware_location is None and args.scan_location is None:
        print ("[X] Must providelocation of the malware on the remote system")
        sys.exit(1)
    elif args.malware_location is None:
        args.malware_location = args.scan_location
    elif args.scan_location is None:
        args.scan_location = args.malware_location

    if args.total_files is None and args.scan_location is None:
        print ("[X] Must provide total files or a directory to scan, please")
        sys.exit(1)
    elif args.total_files is None:
        try:
            args.total_files = len(os.listdir(args.scan_location))
        except:
            print ("[X] Must provide a directory to scan, please")
            sys.exit(1)


    if args.sqlite_location is None:
        print ("[X] Must provide sqlite location")
        sys.exit(1)

    try:
        os.stat(args.sqlite_location)
    except:
        init_database(args.sqlite_location)


    window = long(float(args.total_files) / len(args.hosts))
    extra = 0

    if args.total_files != window * len(args.hosts):
        extra = args.total_files - (window * len(args.hosts))

    offsets = []
    pos = 0
    offset = 0
    commands = []
    cnt = 0
    while pos < len(args.hosts):
        start = offset
        end = offset+window
        cmd = generate_command(args.avlabel_location, args.malware_location, start, end)
        if extra > 0 and pos == len(args.hosts) -1:
            cmd = generate_command(args.avlabel_location, args.malware_location, start, end+extra)
        commands.append(cmd)
        offset += window
        pos += 1

    perform_fp_scan_hosts(args.user, args.password, args.hosts, commands, args.sqlite_location, debug=args.debug)
    etime = datetime.now()
    print ("fp_scan_remote_stdout: Started: %s"%stime.strftime("%H:%M:%S.%f %m-%d-%Y"))
    print ("fp_scan_remote_stdout: Ended: %s"%etime.strftime("%H:%M:%S.%f %m-%d-%Y"))


#python fpscan_avlabeling_remote.py -user UsErNaMe -password PaSSw0rd -hosts fprotect-workx32-00 fprotect-workx32-01 fprotect-workx32-02 fprotect-workx32-03 fprotect-workx32-04 fprotect-workx32-05 fprotect-workx32-11 fprotect-workx32-12 fprotect-workx32-13 fprotect-workx32-14 fprotect-workx32-15 -malware_location /srv/nfs/malware_scan/ -avlabel_location /home/fprotect/avlabeling/ -total_files 131072 -sqlite_location /research_data/fpscan_hash_results.db

