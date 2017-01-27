import sys, argparse, threading, json, shlex, time
import subprocess, traceback, os, sys, sqlite3
from basic_multi_host_commands import *

from datetime import datetime

parser = argparse.ArgumentParser(description="Perform fpscan on remote Linux hosts with paramiko")
parser.add_argument('-cmd', help='command to run', type=str)
parser.add_argument('-args', nargs='*', help='command args to use', type=str)


def rmfile(fname):
    os.remove(fname)

def mt_rm_files(directory):
    files = [os.path.join(directory, i) for i in os.listdir(directory)]
    threads = []
    for fname in files:
        t = threading.Thread(target=rmfile, args=(fname,))
        t.start()
        threads.append(t)

    while len(threads) > 0:
        _threads = []
        for t in threads:
            if t.is_alive():
                _threads.append(t)
        threads = _threads

SUPPORTED_CMDS = {'mt_rm':mt_rm_files, }
if __name__ == '__main__':
    args = parser.parse_args()

    if args.cmd is None or not args.cmd in SUPPORTED_CMDS:
        print ('[X] Please supply a valid command:\n%s'%"\n".join(SUPPORTED_CMDS.keys()))
        sys.exit(1)

    fn = SUPPORTED_CMDS[args.cmd]
    if args.args is None:
        fn()
    else:
        fn(*args.args)


