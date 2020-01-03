#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###################################################
#........../\./\...___......|\.|..../...\.........#
#........./..|..\/\.|.|_|._.|.\|....|.c.|.........#
#......../....../--\|.|.|.|i|..|....\.../.........#
#        Mathtin (c)                              #
###################################################
#   Author: Daniel [Mathtin] Shiko                #
#   Copyright (c) 2020 <wdaniil@mail.ru>          #
#   This file is released under the MIT license.  #
###################################################

__author__ = 'Mathtin'

import subprocess
import platform
import logging
import logging.config
import os
import sys
import re
import time
import threading
import psutil

PLATFROM = platform.system()

# include netcat instances as game instances (for testing purpose)
INCLUDE_NETCAT = True

LOGGING_CONFIG = { 
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'standard': { 
            'format': '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
        },
    },
    'handlers': { 
        'default': { 
            'level': 'DEBUG',
            'formatter': 'standard',
            'class': 'logging.StreamHandler',
            'stream': 'ext://sys.stdout',
        },
    },
    'loggers': {
        'mineportproxy': {
            'handlers': ['default'],
            'level': 'DEBUG'
        },
    } 
}

logging.config.dictConfig(LOGGING_CONFIG)

log = logging.getLogger('mineportproxy')

#############
## UTILITY ##
#############

def check_binary(program):
    def is_exe(fpath):
        return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

    fpath, _ = os.path.split(program)
    if fpath:
        if is_exe(program):
            return program
    else:
        for path in os.environ['PATH'].split(os.pathsep):
            exe_file = os.path.join(path, program)
            if is_exe(exe_file):
                return exe_file

    return None

def shell(cmd):
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    return proc.communicate()

platform_specific_lib = {}
def platform_specific(pl):
    def wrapper(func):
        name = func.__name__
        if pl == PLATFROM:
            platform_specific_lib[name] = func
        elif name not in platform_specific_lib:
            def unimplemented(*args, **kwargs):
                raise Exception('%s in not implemented for current platform' % name)
            platform_specific_lib[name] = unimplemented
        return func
    return wrapper

def bind_platform_funcs():
    current_module = __import__(__name__)
    for name in platform_specific_lib.keys():
        setattr(current_module, name, platform_specific_lib[name])

def check_platform_support():
    log.debug('Checking for platform support')
    if PLATFROM not in ['Linux', 'Windows']:
        log.error('Unsupported platfrom: %s' % platform.platform())
        return False
    
    if PLATFROM == 'Windows':
        if platform.win32_ver()[0] not in ['7', '10']:
            log.error('Unsupported Windows version: %s' % platform.platform())
            return False

        import ctypes
        if ctypes.windll.shell32.IsUserAnAdmin() == 0:
            log.error('netsh requires elevation')
            log.error('Run script as administrator')
            return False


    if PLATFROM == 'Linux':
        if check_binary('iptables') is None:
            log.error('iptables not found')
            return False
        if check_binary('iptables-save') is None:
            log.error('iptables-save not found')
            return False
            
        if check_binary('netstat') is None:
            log.error('netstat not found')
            return False

        _, nat_err = shell('iptables -t nat -L')

        if b'Table does not exist' in nat_err:
            log.error('Kernel does not support forwarding')
            return False

        if b'Permission denied' in nat_err:
            log.error('Insufficient permissions to modify iptables rules')
            log.error('Restart script as root')
            return False

        netstat_out, _ = shell('netstat -lntp')

        lines = [l for l in netstat_out.decode('ascii').splitlines() if 'LISTEN' in l]
        for line in lines:
            line = [l for l in line.split(' ') if l]
            if line[-1] == '-':
                log.error('Insufficient permissions to identify pids with netstat')
                log.error('Restart script as root')
                return False

    log.debug('Current platform is supported')
    return True

#######################
## PLATFORM SPECIFIC ##
#######################

@platform_specific('Linux')
def get_rule(from_port, to_port):
    cmd = 'iptables-save'
    out, err = shell(cmd)
    if err:
        log.error('IPTABLES: ' % err.decode('ascii'))

    # parse iptables dump (from *nat line till COMMIT line)
    dump = out.decode('ascii')
    rule_lines = dump[dump.index('*nat'):]
    rule_lines = dump[:dump.index('COMMIT')].splitlines()
    rules = []

    for line in rule_lines:
        if ('--dport %d' % from_port) in line and ('--to-ports %d' % to_port):
            iport = int(re.search(r'--dport (\d+)', line).group(1))
            oport = int(re.search(r'--to-ports (\d+)', line).group(1))
            oaddr = re.search(r'-s ([0-9.]+)', line).group(1)
            return (iport, oport, oaddr, line)

    return None

@platform_specific('Windows')
def get_rule(from_port, to_port):
    cmd = 'netsh interface portproxy dump'
    out, err = shell(cmd)
    if err:
        log.error('NETSH: ' % err.decode('ascii'))

    # parse dump command (from reset line till popd line)
    dump = out.decode('ascii')
    rule_lines = dump[dump.index('reset'):dump.index('popd')].splitlines()
    rules = []

    for line in rule_lines:
        if ('listenport=%d' % from_port) in line and ('connectport=%d' % to_port):
            iport = int(re.search(r'listenport=(\d+)', line).group(1))
            oport = int(re.search(r'connectport=(\d+)', line).group(1))
            oaddr = re.search(r'connectaddress=([0-9.]+)', line).group(1)
            return (iport, oport, oaddr, line)

    return None

@platform_specific('Linux')
def add_rule(from_port, to_port):
    cmd1 = 'iptables -t nat -A PREROUTING -s 127.0.0.1 -p tcp --dport %d -j REDIRECT --to %d'
    cmd2 = 'iptables -t nat -A OUTPUT -s 127.0.0.1 -p tcp --dport %d -j REDIRECT --to %d'
    out1, err = shell(cmd1 % (from_port, to_port))
    if err:
        log.error('IPTABLES: ' % err.decode('ascii'))
    if len(out1) > 3:
        log.info('IPTABLES: ' % out1.decode('ascii'))
    out2, err = shell(cmd2 % (from_port, to_port))
    if err:
        log.error('IPTABLES: ' % err.decode('ascii'))
    if len(out2) > 3:
        log.info('IPTABLES: ' % out2.decode('ascii'))
    return out1 + out2

@platform_specific('Windows')
def add_rule(from_port, to_port):
    cmd = 'netsh interface portproxy add v4tov4 listenport=%d listenaddress=0.0.0.0 connectport=%d connectaddress=127.0.0.1'
    out, err = shell(cmd % (from_port, to_port))
    if err:
        log.error('NETSH: ' % err.decode('ascii'))
    if len(out) > 3:
        log.info('NETSH: ' % out.decode('ascii'))
    return out

@platform_specific('Linux')
def drop_rule(rule):
    cmd1 = 'iptables -t nat -D PREROUTING -s 127.0.0.1 -p tcp --dport %d -j REDIRECT --to %d'
    cmd2 = 'iptables -t nat -D OUTPUT -s 127.0.0.1 -p tcp --dport %d -j REDIRECT --to %d'
    out1, err = shell(cmd1 % (rule[0], rule[1]))
    if err:
        log.error('IPTABLES: ' % err.decode('ascii'))
    if len(out1) > 3:
        log.info('IPTABLES: ' % out1.decode('ascii'))
    out2, err = shell(cmd2 % (rule[0], rule[1]))
    if err:
        log.error('IPTABLES: ' % err.decode('ascii'))
    if len(out2) > 3:
        log.info('IPTABLES: ' % out2.decode('ascii'))
    return out1 + out2

@platform_specific('Windows')
def drop_rule(rule):
    cmd = 'netsh interface portproxy delete v4tov4 listenport=%d listenaddress=0.0.0.0'
    out, err = shell(cmd % (rule[0]))
    if err:
        log.error('NETSH: ' % err.decode('ascii'))
    if len(out) > 3:
        log.info('NETSH: ' % out.decode('ascii'))
    return out

@platform_specific('Linux')
def get_listening_ports(pid):
    cmd = 'netstat -nltp'
    out, err = shell(cmd)
    if err:
        log.error('NETSH: ' % err.decode('ascii'))

    lines = out.decode('ascii').splitlines()
    ports = set()
    for line in lines:
        if 'tcp' not in line or 'LISTEN' not in line:
            continue
        line = [x for x in line.split(' ') if x]
        if line[-1].split('/')[0] == str(pid):
            ports.add(int(line[3].split(':')[-1])) # add listening port to set as int
    return list(ports)

@platform_specific('Windows')
def get_listening_ports(pid):
    cmd = 'netstat.exe -ano'
    out, err = shell(cmd)
    if err:
        log.error('NETSH: ' % err.decode('ascii'))

    lines = out.decode('ascii').splitlines()
    ports = set()
    for line in lines:
        if 'TCP' not in line or 'LISTENING' not in line:
            continue
        line = [x for x in line.split(' ') if x]
        if line[-1] == str(pid):
            ports.add(int(line[1].split(':')[-1])) # add listening port to set as int
    return list(ports)

def get_game_processes():
    games = []
    for proc in psutil.process_iter():
        try:
            pinfo = proc.as_dict(attrs=['pid', 'name'])
            # assume minecraft runned by java process with word 'minecraft' in args
            if 'java' in pinfo['name']:
                for arg in proc.cmdline():
                    if 'minecraft' in arg.lower(): 
                        games.append(pinfo)
                        break
            if INCLUDE_NETCAT and ('nc.exe' == pinfo['name'] or 'nc' == pinfo['name']):
                games.append(pinfo)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return games


#############################
## MINE PORT PROXY MANAGER ##
#############################

class MinePortProxy(object):
    def __init__(self, port_start=25565, port_end=None):
        super().__init__()

        if port_end is None:
            port_end = port_start

        self.instances = []
        self.pids = []

        self.port_pool = set(range(port_start, port_end+1))

    def filter_old_instances(self):
        live_instances = []
        live_pids = []

        for pid, rule in self.instances:
            ports = get_listening_ports(pid)
            if len(ports) == 0 or ports[0] != rule[1]: # assume that instance listens only one port
                drop_rule(rule)
                self.port_pool.add(rule[0])
                log.info('Old instance (pid %d) dropped (rule %d -> %d)' % (pid, rule[0], rule[1]))
            else:
                live_instances.append((pid, rule))
                live_pids.append(pid)
        
        self.instances = live_instances
        self.pids = live_pids

    def load_new_instances(self):
        for game in get_game_processes():
            pid = game['pid']
            if pid in self.pids:
                continue
            ports = get_listening_ports(pid)
            if len(ports) == 0:
                continue
            if len(self.port_pool) == 0:
                log.info('Cannot load new instance (pid %s), not enough ports' % pid)
                continue
            from_port = self.port_pool.pop()
            to_port = ports[0] # assume that instance listens only one port
            add_rule(from_port, to_port)
            rule = get_rule(from_port, to_port)
            if rule is None:
                log.error('Failed to add rule %d -> %d' % (from_port, to_port))
                continue
            self.instances.append((pid, rule))
            self.pids.append(pid)
            log.info('New instance (pid %d) added (rule %d -> %d)' % (pid, rule[0], rule[1]))

    def run_loop(self):
        while True:
            self.filter_old_instances()
            self.load_new_instances()
            time.sleep(1)

    def close(self):
        for _, rule in self.instances:
            drop_rule(rule)
            self.port_pool.add(rule[0])
        self.instances = []
        self.pids = []

class MinePortProxyThreaded(MinePortProxy):
    def __init__(self, *args):
        super().__init__(*args)

        self.thread = threading.Thread(target=self.run_thread_loop, args=())
        self.stop_event = threading.Event()
        self.started = False

    def run_thread_loop(self):
        while not self.stop_event.is_set():
            self.filter_old_instances()
            self.load_new_instances()
            time.sleep(1)
        self.close()

    def start(self):
        if self.started == True:
            raise Exception('MinePortProxyDaemon already started')
        self.started = True
        self.thread.start()

    def stop(self):
        if self.started == False:
            raise Exception('MinePortProxyDaemon is not started')
        self.stop_event.set()
        self.thread.join()
        self.started = False
        self.stop_event.clear()

def main(argv):
    port_start = 25565

    if len(argv) > 1:
        if argv[1] == '-h':
            print('Usage: %s [port_start] [port_end]')
            return 0
        try:
            port_start = int(argv[1])
        except ValueError:
            print('Usage: %s [port_start] [port_end]')
            return - 1
            
    port_end = port_start

    if len(argv) > 2:
        try:
            port_end = int(argv[2])
        except ValueError:
            print('Usage: %s [port_start] [port_end]')
            return - 1

    if port_start > port_end or port_start < 1 or port_end > 65534:
            print('Invalid port range')
            return - 1
            
    if check_platform_support() is False:
        return - 1

    manager = MinePortProxyThreaded(port_start, port_end)
    manager.start()

    while True:
        try:
            inp = input()
            if inp == 'quit' or inp == 'q':
                log.info('Shutting down')
                break
        except KeyboardInterrupt:
            log.info('Shutting down')
            break

    manager.stop()

    return 0

bind_platform_funcs()
if __name__ == '__main__':
    res = main(sys.argv)
    exit(res)
