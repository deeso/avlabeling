import subprocess, traceback, os, sys, sqlite3, json
from datetime import datetime

def time_str():
    return str(datetime.now().strftime("%H:%M:%S.%f %m-%d-%Y"))

START_DATA_TERM = "=====START_DATA_DUMP====="
END_DATA_TERM = "=====END_DATA_DUMP====="
# print ("Started: %s"%stime.strftime("%H:%M:%S.%f %m-%d-%Y"))
# print ("Ended: %s"%etime.strftime("%H:%M:%S.%f %m-%d-%Y"))
COMPLETED_TERM = "=====COMPLETED====="
CLAMSCAN_ARGS = "clamscan {target_files}"
def create_clamscan_cmd(target_files):
    keyed = {'target_files':" ".join(target_files)}
    return CLAMSCAN_ARGS.format(**keyed)

def perform_clamscan(target_files):
    clamscan_command = create_clamscan_cmd(target_files)
    #print ("Experiment Log: zipiing the memory file %s"%dump_file)
    #print ("Experiment Log: zip command: %s and list:[%s]"%(zip_command, zip_command.split()))
    data = None
    try:
        #print clamscan_command.split()
        p = subprocess.Popen(clamscan_command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        #CP_LOCK.acquire()
        #COMPRESSION_PROCS.append((p, dump_file, True))
        try:
            data = p.communicate()[0]
        except:
            traceback.print_exc()
        res = 0
    except:
        traceback.print_exc()
    finally:
        # CP_LOCK.release()
        pass
    return data

SPLIT_ON_THIS = '''----------- SCAN SUMMARY -----------'''
LABEL_SEP = ': '
VIRUS_SHARE_HASH = "VirusShare_"
TAIL = ' FOUND'
def post_process_data(raw_results, malware_location=None):
    results = raw_results.split(SPLIT_ON_THIS)[0].strip()
    lines = [i for i in results.splitlines()]
    hash_results = {}
    for line in lines:
        if line.find(LABEL_SEP) == -1:
            print ("[X] Line does not contain a LABEL_SEP separator: %s"%line)
            continue
        f, l = line.split(LABEL_SEP)
        l = l.strip(TAIL)
        if f.find(VIRUS_SHARE_HASH) == -1:
            print ("[X] File entry does not contain a VIRUS_SHARE separator: %s"%f)
            continue
        h = f.split(VIRUS_SHARE_HASH)[1].strip()
        hash_results[h] = (l.strip(), line)
    return hash_results

def read_samples_directory(malware_location):
    files = [os.path.join(malware_location, i) for i in os.listdir(malware_location)]
    return files

if __name__ == '__main__':
    #print sys.argv
    malware_location = sys.argv[1]
    start = int(sys.argv[2])
    end = int(sys.argv[3])
    #output_sqllite_db = sys.argv[4]
    stime = datetime.now()
    samples = read_samples_directory(malware_location)
    end = len(samples) if end > len(samples) else end
    the_files = samples[start:end]
    hashes_labels = {}
    #try:
    #    os.stat(output_sqllite_db)
    #except:
    #    init_database(output_sqllite_db)

    pos = 0
    window = 200
    _end = len(the_files)
    while pos < _end:
        window = window if pos+window < _end else _end-pos+1
        target_files = the_files[pos:pos+window]
        res = perform_clamscan(target_files)
        _hashes_labels = post_process_data(res)
        hashes_labels.update(_hashes_labels)
        print ("[=] Processed %d files @ %d"%(len(_hashes_labels), pos+start))
        pos += window

    #if len(hashes_labels) > 0:
    #    write_files_results(hashes_labels, output_sqllite_db)

    etime = datetime.now()

    #print ("Started: %s"%stime.strftime("%H:%M:%S.%f %m-%d-%Y"))
    #print ("Ended: %s"%etime.strftime("%H:%M:%S.%f %m-%d-%Y"))
    print (START_DATA_TERM)
    print (json.dumps(hashes_labels))
    print (END_DATA_TERM)
    etime = datetime.now()
    print ("Started: %s"%stime.strftime("%H:%M:%S.%f %m-%d-%Y"))
    print ("Ended: %s"%etime.strftime("%H:%M:%S.%f %m-%d-%Y"))
    print (COMPLETED_TERM)

#python clamscan_avlabeling.py /research_data/malware_scan/ 0 5700 /research_data/clamscan_hash_labels.db &
#python clamscan_avlabeling.py /research_data/malware_scan/ 5700 11400 /research_data/clamscan_hash_labels.db &
#python clamscan_avlabeling.py /research_data/malware_scan/ 11400 17100 /research_data/clamscan_hash_labels.db &
#python clamscan_avlabeling.py /research_data/malware_scan/ 17100 22800 /research_data/clamscan_hash_labels.db &
#python clamscan_avlabeling.py /research_data/malware_scan/ 22800 28500 /research_data/clamscan_hash_labels.db &
#python clamscan_avlabeling.py /research_data/malware_scan/ 28500 34200 /research_data/clamscan_hash_labels.db &
#python clamscan_avlabeling.py /research_data/malware_scan/ 34200 39900 /research_data/clamscan_hash_labels.db &
#python clamscan_avlabeling.py /research_data/malware_scan/ 39900 45600 /research_data/clamscan_hash_labels.db &
#python clamscan_avlabeling.py /research_data/malware_scan/ 45600 51300 /research_data/clamscan_hash_labels.db &
#python clamscan_avlabeling.py /research_data/malware_scan/ 51300 57000 /research_data/clamscan_hash_labels.db &
#python clamscan_avlabeling.py /research_data/malware_scan/ 57000 62700 /research_data/clamscan_hash_labels.db &
#python clamscan_avlabeling.py /research_data/malware_scan/ 62700 68400 /research_data/clamscan_hash_labels.db &
#python clamscan_avlabeling.py /research_data/malware_scan/ 68400 74100 /research_data/clamscan_hash_labels.db &
#python clamscan_avlabeling.py /research_data/malware_scan/ 74100 79800 /research_data/clamscan_hash_labels.db &
#python clamscan_avlabeling.py /research_data/malware_scan/ 79800 85500 /research_data/clamscan_hash_labels.db &
#python clamscan_avlabeling.py /research_data/malware_scan/ 85500 91200 /research_data/clamscan_hash_labels.db &
#python clamscan_avlabeling.py /research_data/malware_scan/ 91200 96900 /research_data/clamscan_hash_labels.db &
#python clamscan_avlabeling.py /research_data/malware_scan/ 96900 102600 /research_data/clamscan_hash_labels.db &
#python clamscan_avlabeling.py /research_data/malware_scan/ 102600 108300 /research_data/clamscan_hash_labels.db &
#python clamscan_avlabeling.py /research_data/malware_scan/ 108300 114000 /research_data/clamscan_hash_labels.db &
#python clamscan_avlabeling.py /research_data/malware_scan/ 114000 119700 /research_data/clamscan_hash_labels.db &
#python clamscan_avlabeling.py /research_data/malware_scan/ 119700 125400 /research_data/clamscan_hash_labels.db &
#python clamscan_avlabeling.py /research_data/malware_scan/ 125400 131100 /research_data/clamscan_hash_labels.db &

