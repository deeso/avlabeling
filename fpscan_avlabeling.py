import subprocess, traceback, os, sys, sqlite3
from datetime import datetime

def time_str():
    return str(datetime.now().strftime("%H:%M:%S.%f %m-%d-%Y"))

FPSCAN_ARGS = "fpscan --report --applications --adware {target_files}"
def create_fpscan_cmd(target_files):
    keyed = {'target_files':" ".join(target_files)}
    return FPSCAN_ARGS.format(**keyed)

def perform_fpscan(target_files):
    fpscan_command = create_fpscan_cmd(target_files)
    #print ("Experiment Log: zipiing the memory file %s"%dump_file)
    #print ("Experiment Log: zip command: %s and list:[%s]"%(zip_command, zip_command.split()))
    data = None
    try:
        #print clamscan_command.split()
        p = subprocess.Popen(fpscan_command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
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

LABEL_SEP = '] <'
VIRUS_SHARE_HASH = "VirusShare_"
INFECTED_OBJECTS = "[Contains infected objects]"
def post_process_data(raw_results, base_location=None):
    lines = [i.strip() for i in raw_results.splitlines() if i.find('[') == 0]
    hash_results = {}
    for line in lines:
        label = None
        if line.find(LABEL_SEP) == -1 and line.find(INFECTED_OBJECTS) == 0:
            label = ''
        elif line.find(LABEL_SEP) == -1:
            print ("[X] Line does not contain a LABEL_SEP separator: %s"%line)
            continue
        else:
            label = line.split(LABEL_SEP)[1].split()[0]
        label = label.strip().strip('>')

        if line.find(VIRUS_SHARE_HASH) == -1:
            print ("[X] File entry does not contain a VIRUS_SHARE separator: %s"%line)
            continue

        h = line.split('VirusShare_')[1][:32]
        
        hash_results[h] = (label, line.strip())
    return hash_results

def read_samples_directory(base_location):
    files = [os.path.join(base_location, i) for i in os.listdir(base_location)]
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
    base_location = sys.argv[1]
    start = int(sys.argv[2])
    end = int(sys.argv[3])
    output_sqllite_db = sys.argv[4]
    try:
        os.stat(output_sqllite_db)
    except:
        init_database(output_sqllite_db)

    stime = datetime.now()
    samples = read_samples_directory(base_location)
    end = len(samples) if end > len(samples) else end
    the_files = samples[start:end]
    hashes_labels = {}
    pos = 0
    window = 200
    _end = len(the_files)
    while pos < _end:
        window = window if pos+window < _end else _end-pos+1
        target_files = the_files[pos:pos+window]
        res = perform_fpscan(target_files)
        _hashes_labels = post_process_data(res)
        hashes_labels.update(_hashes_labels)
        print ("[=] Processed %d files @ %d"%(len(_hashes_labels), pos+start))
        pos += window

    if len(hashes_labels) > 0:
        write_files_results(hashes_labels, output_sqllite_db, 'fpscan')

    etime = datetime.now()

    print ("Started: %s"%stime.strftime("%H:%M:%S.%f %m-%d-%Y"))
    print ("Ended: %s"%etime.strftime("%H:%M:%S.%f %m-%d-%Y"))
