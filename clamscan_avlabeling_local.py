import sys, argparse, threading, json, shlex, time
import subprocess, traceback, os, sys, sqlite3
from basic_multi_host_commands import *

from datetime import datetime


parser = argparse.ArgumentParser(description="Perform fpscan on remote Linux hosts with paramiko")
parser.add_argument('-user', help='user to log in with', type=str)
parser.add_argument('-password', help='user to log in with', type=str)
parser.add_argument('-malware_location', help='local directory with the malware', type=str)
parser.add_argument('-avlabel_location', help='base location of avlabeling code on system', type=str)
parser.add_argument('-scan_location', help='Scan for the number of files so work is spread evenly', type=str)
parser.add_argument('-num_procs', help='Number of scans to run concurrently', type=int, default=1)
parser.add_argument('-total_files', help='Number of files so work is spread evenly', type=int)
parser.add_argument('-sqlite_location', help='Location of the sqlite_db', type=str)
parser.add_argument('-debug', help='dump raw logs from all the host in the current directory', action="store_true", default=False)

START_DATA_TERM = "=====START_DATA_DUMP====="
END_DATA_TERM = "=====END_DATA_DUMP====="
# print ("Started: %s"%stime.strftime("%H:%M:%S.%f %m-%d-%Y"))
# print ("Ended: %s"%etime.strftime("%H:%M:%S.%f %m-%d-%Y"))
COMPLETED_TERM = "=====COMPLETED====="
CLAMSCAN_AVLABEL_CMD = "python {avlabel_location}/clamscan_avlabeling_stdout.py {malware_location} {start} {end}"

def generate_command(avlabel_location, malware_location, start, end):
    cmd_dict = {'avlabel_location':avlabel_location, 'malware_location':malware_location, 'start':start, 'end':end}
    cmd = CLAMSCAN_AVLABEL_CMD.format(**cmd_dict)
    return cmd

def time_str():
    return str(datetime.now().strftime("%H:%M:%S.%f %m-%d-%Y"))

def perform_clamav_scan(identifiers, commands, output_sqllite_db, debug=False):
    threads = []
    pos = 0
    while pos < len(commands):
        command = commands[pos]
        identifier = identifiers[pos%len(identifiers)]
        t = threading.Thread(target=execute_local_command, args=(identifier, command, output_sqllite_db, debug))
        print ("[=] %s Started Identifier (%s) command: %s"%(time_str(), identifier, command))
        t.start()
        threads.append(t)
        # Give thread time to login and start working before starting next onw
        time.sleep(10)
        pos += 1

    print ("[=] %s All commands started waiting for the threads to complete."%(time_str()))
    for t in threads:
        t.join()

def execute_local_command(identifier, command, output_sqllite_db, debug=False):
    data = exec_command(command)
    process = True
    _data = "".join(data)
    if debug:
        open("%s-debug.log"%identifier, 'a').write(_data)

    if _data.find(START_DATA_TERM) == -1:
        print ("[X] Identifier (%s) failed to get back data, no data start"%(identifier))
        process = False

    if _data.find(END_DATA_TERM) == -1:
        print ("[X] Identifier (%s) failed to get back data, no data end"%(identifier))
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
                print ("[X] Identifier (%s) failed to get back data, no JSON data"%(identifier))
                process = False
        except:
            print ("[X] Identifier (%s) failed to get back data, JSON data unparseable"%(identifier))
            process = False
    completed = "[=] Finished execution %s"%time_str()
    if _data.find(COMPLETED_TERM) > 0:
        completed = _data.split(END_DATA_TERM)[1].split(COMPLETED_TERM)[0] + "\n" + completed


    if process:
        print ("[+] Identifier (%s) successfully completed scan.\n%s"%(identifier, completed))
    else:
        print ("[X] Identifier (%s) failed to complete scan.\n%s"%(identifier, completed))

def read_samples_directory(malware_location):
    files = [os.path.join(malware_location, i) for i in os.listdir(malware_location)]
    return files

def write_files_results(hash_results, output_sqllite_db, av_engine='clamav'):
    conn = sqlite3.connect(output_sqllite_db)
    conn.text_factory = str
    c = conn.cursor()
    rows = []
    for h,l_m in hash_results.items():
        l, m = l_m
        rows.append((h,l, m, av_engine))
    c.executemany("INSERT INTO hash_labels VALUES (?,?,?,?)", rows)
    conn.commit()

def init_database(output_sqllite_db):
    conn = sqlite3.connect(output_sqllite_db)
    c = conn.cursor()
    c.execute('''CREATE TABLE hash_labels (hash, label, meta, av_engine)''')
    c.close()
    conn.commit()

if __name__ == '__main__':
    #print sys.argv

    args = parser.parse_args()
    stime = datetime.now()

    if args.malware_location is None and args.scan_location is None:
        print ("[X] Must providelocation of the malware on the local system")
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

    print args.total_files
    if args.sqlite_location is None:
        print ("[X] Must provide sqlite location")
        sys.exit(1)

    try:
        os.stat(args.sqlite_location)
    except:
        init_database(args.sqlite_location)

    args.num_procs = args.num_procs if args.num_procs > 0 else 1
    window = long(float(args.total_files) / args.num_procs)
    extra = 0

    if args.total_files != window * args.num_procs:
        extra = args.total_files - (window * args.num_procs)

    offsets = []
    pos = 0
    offset = 0
    commands = []
    cnt = 0
    identifiers = []
    while pos < args.num_procs:
        start = offset
        end = offset+window
        cmd = generate_command(args.avlabel_location, args.malware_location, start, end)
        if extra > 0 and pos == args.num_procs -1:
            cmd = generate_command(args.avlabel_location, args.malware_location, start, end+extra)
        commands.append(cmd)
        identifiers.append("JobFiles-%06d-%06d"%(start, end))
        offset += window
        pos += 1


    perform_clamav_scan(identifiers, commands, args.sqlite_location, debug=args.debug)
    etime = datetime.now()
    print ("clamav_scan_remote_stdout: Started: %s"%stime.strftime("%H:%M:%S.%f %m-%d-%Y"))
    print ("clamav_scan_remote_stdout: Ended: %s"%etime.strftime("%H:%M:%S.%f %m-%d-%Y"))


#python clamscan_avlabeling_local.py -num_procs 22 -scan_location /research_data/malware_scan/ -malware_location /research_data/malware_scan/ -avlabel_location /research_data/code/git/avlabeling/ -sqlite_location /research_data/clamavscan_hash_results.db

