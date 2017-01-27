import paramiko, re, time, sys, libvirt, threading, socket, subprocess, shlex
from datetime import datetime
from socket import error as socket_error


MAKE_SAFE_FOR_QEMU = False
MAX_RETRYS = 3
MAX_RETRY_SLEEP = 4.0
SLEEP_SECS = 3
SLEEP_SECS_LONG = 30
REBOOT = '''sudo sh -c "reboot"'''
SHUTDOWN = '''sudo sh -c "shutdown -h now"'''
QEMU_PRIO = -10
JAVA_PRIO = 20

def time_str():
    return str(datetime.now().strftime("%H:%M:%S.%f %m-%d-%Y"))

def exec_command (cmd, shell=False):
    cmdlist = []
    if isinstance(cmd, list):
        cmdlist = cmd
        cmd = " ".join(cmd)
    elif isinstance(cmd, str):
        cmdlist = cmd.split()
    else:
        raise Exception("exec_command requires a string or list as a parameter")

    #print ("%s: Executing cmd: %s"%(time_str(), cmd ))
    p = subprocess.Popen(shlex.split(cmd), shell=shell, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    content = None
    try:
        content = p.communicate()[0].decode('iso8859-1', 'replace')
        p.wait()
        content = content + p.communicate()[0].decode('iso8859-1', 'replace')
    except:
        pass

    if content:
         content = content.replace('\x1b[0K\n', '').replace('\x1b[0K\r', '')
    return content


def time_str():
    return str(datetime.now().strftime("%H:%M:%S.%f %m-%d-%Y"))

def determine_host_ip_addr(client):
    ip_address = None
    try:
        ip_address = socket.gethostbyname(client)
        return ip_address
    except:
        pass
    virt_conn = open_virt_connection()
    if virt_conn:
        try:
            dom = virt_conn.lookupByName(client)
            ip_address = None
            mac_address = dom.XMLDesc(0).split("<mac address='")[1].split("'/>")[0]
            process = subprocess.Popen(['/usr/sbin/arp', '-n'], stdout=subprocess.PIPE,
                                               stderr=subprocess.STDOUT)
            process.wait()  # Wait for it to finish with the command
            for line in process.stdout.readlines():
                if line.find(mac_address) > -1:
                    #print line
                    ip_address = line.split()[0]
                    add_host_ip_mapping(client, ip_address)
                    break
        except:
            pass

    close_virt_connection(virt_conn)
    return ip_address

def get_host_ip(host):
    ipadd = determine_host_ip_addr(host)
    if ipadd is None:
        raise Exception("Could not resolve vm name: %s"%host)
    return ipadd

def ssh_to_target (hostname, username, password):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(hostname, username=username, password=password)
    return client

def exec_cmds(client, password, cmds):
    data = []
    for cmd in cmds:
        print "Executing command: ", cmd
        transport = client.get_transport()
        session = transport.open_session()
        session.set_combine_stderr(True)
        session.get_pty()
        session.exec_command(cmd)
        stdin = session.makefile('wb', -1)
        stdout = session.makefile('rb', -1)
        #you have to check if you really need to send password here
        stdin.write(password +'\n')
        stdin.flush()
        session.recv_exit_status()
        d = ''
        try:
            d = stdout.read()
        except:
            pass
        data.append(d)
    return data

def perform_command_set_nfs(user, password, host, cmd_list):
    print "connecting to host:", host
    try:
        client = ssh_to_target(host, username=user, password=password)
        #sifipr.wait_till_accessible(client)
        exec_cmds (client, password, cmd_list)
    except:
        print ("Unable to log into the host: %s"%(host))

def perform_command_set(user, password, host, cmd_list):
    print "connecting to host:", host
    try:
        client = ssh_to_target(host, username=user, password=password)
        exec_cmds (client, password, cmd_list)
    except:
        print ("Unable to log into the host: %s"%(host))

def perform_command_set_on_hosts(user, password, host_list, cmd_list, do_reboot=True):
    if do_reboot:
        cmd_list.append(REBOOT)

    threads = []
    for host in host_list:
        t = threading.Thread(target=perform_command_set, args=(user, password, host, cmd_list))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

def perform_command_set_on_hosts_nfs(user, password, host_list, cmd_list, do_reboot=True):
    if do_reboot:
        cmd_list.append(REBOOT)

    threads = []
    for host in host_list:
        t = threading.Thread(target=perform_command_set_nfs, args=(user, password, host, cmd_list))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()


def perform_reboot_on_hosts(user, password, host_list):
    cmd_list = [REBOOT]
    threads = []
    for host in host_list:
        t = threading.Thread(target=perform_command_set, args=(user, password, host, cmd_list))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

def perform_shutdown_on_hosts(user, password, host_list):
    cmd_list = [SHUTDOWN]
    threads = []
    for host in host_list:
        t = threading.Thread(target=perform_command_set, args=(user, password, host, cmd_list))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

def bounce_host_list(host_list):
    for host in host_list:
        bounce_function(host)

def send_enter_key(dom=None):
    virt_conn = None
    dom_set = False
    try:
        if dom is None:
            dom_set = True
            virt_conn = open_virt_connection()
            dom = virt_conn.lookupByName(client)
        dom.sendKey(0, 0, [28,], 1, 0)
        if dom_set:
            close_virt_connection(virt_conn)
        return True
    except:
        if dom_set:
            close_virt_connection(virt_conn)
        return False

def bounce_function(client):
    stop_function(client)
    time.sleep(SLEEP_SECS)
    start_function(client)
    time.sleep(SLEEP_SECS)

def close_virt_connection(virt_conn):
    if virt_conn:
        try:
            virt_conn.close()
        except:
            pass

def open_virt_connection(uri="qemu:///system"):
    try:
        return libvirt.open(uri)
    except:
        print "XXXX - Failed to open a sockt to libvirt"
        raise
        return None

def start_function (client):
    keyed = {"client":client}
    #cmd  = VIR_START.format(**keyed)
    virt_conn = open_virt_connection()
    res = -1
    if virt_conn:
        print ("%s Experiment Log: starting up %s"%(time_str(), client))
        try:
            dom = virt_conn.lookupByName(client)
            res = dom.create()
            if res == 0:
                time.sleep(1)
                # stupid bootloader menu
                dom.sendKey(0, 0, [28,], 1, 0)
        except:
            pass
    close_virt_connection(virt_conn)
    return res#exec_command(cmd)

def stop_function (client, timeout=.5):
    keyed = {"client":client}
    virt_conn = open_virt_connection()
    res = -1
    if virt_conn:
        try:
            dom = virt_conn.lookupByName(client)
            res = dom.shutdown() if dom.isActive() else 1
            if res == 0:
                print ("%s Experiment Log: Shutting down %s"%(time_str(), client))
            #print ("%s Experiment Log: shutdown sent %s"%(time_str(), client))
            time.sleep(1)
            if dom.isActive() and res == 0:
                dom.destroy()
        except:
            print ("%s Experiment Log: unable to shutdown sent %s"%(time_str(), client))
            pass
    close_virt_connection(virt_conn)
    #cmd  = VIR_STOP.format(**keyed)
    return res#exec_command(cmd)

def start_host_list (host_list):
    threads = []
    for host in host_list:
        t = threading.Thread(target=start_function, args=(host,))
        threads.append(t)
        t.start()
    time.sleep(SLEEP_SECS_LONG)
    for t in threads:
        t.join()
        #time.sleep(SLEEP_SECS)



def stop_host_list(host_list):
    for host in host_list:
        stop_function(host)

def snapshot_function(host):
    keyed = {"client":host}
    cmd  = VIR_SNAPSHOT.format(**keyed)
    return exec_command(cmd)

def snapshot_host_list (host_list):
    for host in host_list:
        snapshot_function(host)

def revert_function(host):
    keyed = {"client":host}
    cmd  = VIR_REVERT.format(**keyed)
    return exec_command(cmd)

def revert_host_list (host_list):
    for host in host_list:
        revert_function(host)

def start_hosts(user, password, host_list):
    start_host_list(host_list)
    time.sleep(SLEEP_SECS)
    up_host = set()
    threads = []
    for h in host_list:
        r = {}
        t = threading.Thread(target=test_host_is_up, args=(h, user, password, r))
        threads.append((t, r))
        t.start()

    for t,r in threads:
        t.join()
        if 'result' in r:
            p = r['result']
            if len(p) > 0:
                up_host.add(p)
    return up_host

def stop_hosts(user, password, host_list):
    # attempt clean shutdown
    perform_shutdown_on_hosts(user, password, host_list)
    time.sleep(SLEEP_SECS_LONG)
    print ("%s: Logged in and shutdown hosts, now forcing shutdown via libvirt if it is up"%(time_str()))
    stop_host_list(host_list)

def test_host_is_up(vmhost, username, password, results={}, restart=True):
    num_retrys = 0
    res = False
    host_ip = get_host_ip(vmhost)
    client = None
    while num_retrys < MAX_RETRYS:
        try:
            print("Testing %s(%s) is up, retrys=%d"%(vmhost, host_ip, num_retrys))
            client = ssh_to_target(host_ip, username, password)
            data = exec_cmds(client, password, ["ls -all /usr/"])
            if len(data[0]) > 0:
                print("Host %s(%s) is up"%(vmhost, host_ip))
                results['result'] = vmhost
                res = True
                break
        except socket_error as serr:
            bounce_function(vmhost)
            time.sleep(20)
            client = None
        except:
            try:
                client.close()
            except:
                pass
            client = None
        if not restart:
            break
        num_retrys+=1
        time.sleep(MAX_RETRY_SLEEP)
    try:
        if client:
            client.close()
    except:
        pass
    if not res:
        bounce_function(vmhost)
    if not res:
        results['result'] = ''
    return res

def pgrep_qemu():
    d = exec_command("pgrep qemu")
    d = d.split()
    r = []
    for i in d:
        try:
            r.append(int(i))
        except:
            pass
    return r

def pgrep_python():
    d = exec_command("pgrep python")
    d = d.split()
    r = []
    for i in d:
        try:
            r.append(int(i))
        except:
            pass
    return r

def pgrep_java():
    d = exec_command("pgrep java")
    d = d.split()
    r = []
    for i in d:
        try:
            r.append(int(i))
        except:
            pass
    return r

def renice(renice_val, pid):
    renice_cmd = 'sudo renice %d -p %d'
    exec_command(renice_cmd%(renice_val, pid))

def renice_qemu(renice_val):
    d = pgrep_qemu()
    for pid in d:
        renice(renice_val, pid)

def renice_java(renice_val):
    d = pgrep_java()
    for pid in d:
        renice(renice_val, pid)

def renice_python(renice_val):
    d = pgrep_python()
    for pid in d:
        renice(renice_val, pid)

def prioritize_qemu():
    renice_qemu(QEMU_PRIO)
    renice_java(JAVA_PRIO)

def prioritize_qemu_thread():
    global MAKE_SAFE_FOR_QEMU
    MAKE_SAFE_FOR_QEMU = True
    while MAKE_SAFE_FOR_QEMU:
        prioritize_qemu()
        time.sleep(60)

def start_prioritize_qemu():
    t = threading.Thread(target=prioritize_qemu_thread)
    t.start()
    return t
