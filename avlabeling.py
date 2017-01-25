import subprocess, traceback, os, sys, sqlite3

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
def post_process_data(raw_results, base_location=None):
    results = raw_results.split(SPLIT_ON_THIS)[0].strip()
    lines = [i for i in results.splitlines()]
    hash_results = {}
    for line in lines:
        f, l = line.split(LABEL_SEP)
        h = f.split(VIRUS_SHARE_HASH)[1].strip()
        hash_results[h] = l.strip()
    return hash_results

def read_samples_directory(base_location):
    files = [os.path.join(base_location, i) for i in os.listdir(base_location)]
    return files

def write_files_results(hash_results, output_sqllite_db, av_engine='clamav'):
    conn = sqlite3.connect(output_sqllite_db)
    c = conn.cursor()
    rows = [(h,l, av_engine) for h,l in hash_results.items()]
    c.executemany("INSERT INTO hash_labels VALUES (?,?,?)", rows)
    conn.commit()


def init_database(output_sqllite_db):
    conn = sqlite3.connect(output_sqllite_db)
    c = conn.cursor()
    c.execute('''CREATE TABLE hash_labels (hash, label, av_engine)''')
    c.close()
    conn.commit()


if __name__ == '__main__':
    base_location = sys.argv[1]
    start = int(sys.argv[2])
    end = int(sys.argv[3])
    output_sqllite_db = sys.argv[4]

    samples = read_samples_directory(base_location)
    the_files = samples[start:end]
    hashes_labels = {}
    pos = 0
    window = 200
    while pos < end:
        target_files = the_files[pos:pos+window]
        res = perform_clamscan(target_files)
        _hashes_labels = post_process_data(res)
        hashes_labels.update(_hashes_labels)
        print ("processed %d files @ %d"%(len(_hashes_labels), pos))
        pos += window

    if len(hashes_labels) > 0:
        write_files_results(hashes_labels, output_sqllite_db)

# python avlabeling.py /research_data/test/   0 2000 /research_data/hash_labels.db

#python avlabeling.py /research_data/test/   0 5700 /research_data/hash_labels.db &
#python avlabeling.py /research_data/test/   5700 11400 /research_data/hash_labels.db &
#python avlabeling.py /research_data/test/   11400 17100 /research_data/hash_labels.db &
#python avlabeling.py /research_data/test/   17100 22800 /research_data/hash_labels.db &
#python avlabeling.py /research_data/test/   22800 28500 /research_data/hash_labels.db &
#python avlabeling.py /research_data/test/   28500 34200 /research_data/hash_labels.db &
#python avlabeling.py /research_data/test/   34200 39900 /research_data/hash_labels.db &
#python avlabeling.py /research_data/test/   39900 45600 /research_data/hash_labels.db &
#python avlabeling.py /research_data/test/   45600 51300 /research_data/hash_labels.db &
#python avlabeling.py /research_data/test/   51300 57000 /research_data/hash_labels.db &
#python avlabeling.py /research_data/test/   57000 62700 /research_data/hash_labels.db &
#python avlabeling.py /research_data/test/   62700 68400 /research_data/hash_labels.db &
#python avlabeling.py /research_data/test/   68400 74100 /research_data/hash_labels.db &
#python avlabeling.py /research_data/test/   74100 79800 /research_data/hash_labels.db &
#python avlabeling.py /research_data/test/   79800 85500 /research_data/hash_labels.db &
#python avlabeling.py /research_data/test/   85500 91200 /research_data/hash_labels.db &
#python avlabeling.py /research_data/test/   91200 96900 /research_data/hash_labels.db &
#python avlabeling.py /research_data/test/   96900 102600 /research_data/hash_labels.db &
#python avlabeling.py /research_data/test/   102600 108300 /research_data/hash_labels.db &
#python avlabeling.py /research_data/test/   108300 114000 /research_data/hash_labels.db &
#python avlabeling.py /research_data/test/   114000 119700 /research_data/hash_labels.db &
#python avlabeling.py /research_data/test/   119700 125400 /research_data/hash_labels.db &
#python avlabeling.py /research_data/test/   125400 131100 /research_data/hash_labels.db &