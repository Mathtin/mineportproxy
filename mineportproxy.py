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
import argparse
import signal

# Determine which OS we are running
PLATFROM = platform.system()

# Include netcat instances as game instances (for testing purpose)
# Switched via args
INCLUDE_NETCAT = False

# Basic seperate log config (level switched via args)
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
            'level': 'INFO',
            'formatter': 'standard',
            'class': 'logging.StreamHandler',
            'stream': 'ext://sys.stderr',
        },
    },
    'loggers': {
        'mineportproxy': {
            'handlers': ['default'],
            'level': 'INFO'
        },
    } 
}

# module logger (setup in main)
log = None

#############
## UTILITY ##
#############

def binary_exists(program):
    ''' Check if binary file exists (by full path or in PATH env variable)

    Parameters:
        program (str): binary file name (or full path name)

    Returns:
        bool: True if binary exists

    '''
    def is_exe(fpath):
        return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

    fpath, _ = os.path.split(program)
    if fpath:
        if is_exe(program):
            return True
    else:
        for path in os.environ['PATH'].split(os.pathsep):
            exe_file = os.path.join(path, program)
            if is_exe(exe_file):
                return True

    return False

def shell(cmd, timeout=1):
    ''' Evaluates command and returns piped stdout and stderr. Note: returns (None, None) on timeout

    Parameters:
        cmd (str): shell command to evaluate
        timeout (float): communicate timeout in seconds (default: 1 sec)

    Returns:
        (bytes, bytes): stdout and stderr output of commmand

    '''
    #log.debug('Executing: %s' % cmd)
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    try:
        return proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        return None, None

platform_specific_lib = {}
def platform_specific(pl):
    ''' Parametric decorator adding function only on specified OS name
        
    Parameters:
        pl (str): OS name

    Returns:
        decorator: actual decorator to gather function

    '''
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
    '''Bind decorated platform specific functions to current module'''
    current_module = __import__(__name__)
    for name in platform_specific_lib.keys():
        setattr(current_module, name, platform_specific_lib[name])

def check_platform_support():
    ''' Checks if current OS capable of running this script

    Returns:
        bool: True if capable

    '''
    log.debug('Checking for platform support')
    log.debug('Detected platform: %s' % PLATFROM)
    if PLATFROM not in ['Linux', 'Windows']:
        log.error('Unsupported platfrom: %s' % platform.platform())
        return False
    
    if PLATFROM == 'Windows':
        win_ver = platform.win32_ver()[0]
        log.debug('Detected Windows version: %s' % win_ver)
        # netsh with portproxy available on Windows 7 and above
        if win_ver not in ['7', '8', '8.1', '10', '11']:
            log.warning('Probably unsupported Windows version: %s' % platform.platform())
        # netsh needs elevated shell
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        log.debug('Running elevated' if is_admin else 'Running not elevated')
        if is_admin == 0:
            log.error('netsh requires elevation')
            log.error('Run script as administrator')
            return False

    if PLATFROM == 'Linux':
        # check neccessary binaries availability
        if binary_exists('iptables') is None:
            log.error('iptables not found')
            return False
        log.debug('iptable present')
        if binary_exists('iptables-save') is None:
            log.error('iptables-save not found')
            return False
        log.debug('iptables-save present')
        if binary_exists('netstat') is None:
            log.error('netstat not found')
            return False
        log.debug('netstat present')
        # check iptables output to determine if current user actually have rights to change firewall settings
        _, nat_err = shell('iptables -t nat -L')
        if nat_err is None: # kali linux iptables stuck on non-root user for some reason
            log.error('iptables not responding')
            log.error('Probably need to restart as root')
            return False
        # WSL 1 response with such error
        if b'Table does not exist' in nat_err:
            log.error('Kernel does not support forwarding')
            return False
        # Obvious insufficient permissions
        if b'Permission denied' in nat_err:
            log.error('Insufficient permissions to modify iptables rules')
            log.error('Restart script as root')
            return False
        log.debug('iptables output accepted')
        # check iptables-save output to determine if current user actually have rights to dump firewall settings
        nat_out, nat_err = shell('iptables-save')
        if nat_err is None or nat_out == b'':  # WSL 1 gives empy response here :/
            log.error('iptables-save not responding')
            log.error('Probably need to restart as root')
            return False
        # Obvious insufficient permissions
        if b'Permission denied' in nat_err:
            log.error('Insufficient permissions to dump iptables rules')
            log.error('Restart script as root')
            return False
        log.debug('iptables-save output accepted')
        # check netstat output to determine if current user have rights to run netstat and id PIDs
        netstat_out, _ = shell('netstat -lntp')
        if netstat_out is None or netstat_out == b'':
            log.error('netstat not responding')
            log.error('Probably need to restart as root')
            return False
        try:
            lines = [l for l in netstat_out.decode('utf-8').splitlines() if 'LISTEN' in l]
        except UnicodeDecodeError:
            log.error('Cannot decode netstat output')
            log.error('NETSTAT OUTPUT:')
            log.error(netstat_out)
            return False
        if len(lines) == 0:
            log.warning('No listening sockets detected via netstat. Can not determine if netstat works properly.')
            log.info('Opening listening socket to recheck netstat')
            import socket
            serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            serversocket.bind((socket.gethostname(), 8789))
            netstat_out, _ = shell('netstat -lntp')
            serversocket.close()
            if netstat_out is None or netstat_out == b'':
                log.error('netstat not responding')
                log.error('Probably need to restart as root')
                return False
            try:
                lines = [l for l in netstat_out.decode('utf-8').splitlines() if 'LISTEN' in l]
            except UnicodeDecodeError:
                log.error('Cannot decode netstat output')
                log.error('NETSTAT OUTPUT:')
                log.error(netstat_out)
                return False
            if len(lines) == 0:
                log.error('No listening sockets detected via netstat')
                log.error('Probably need to restart as root')
                return False
        for line in lines:
            line = [l for l in line.split(' ') if l]
            if line[-1] == '-':
                log.error('Insufficient permissions to identify pids with netstat')
                log.error('Restart script as root')
                return False
        log.debug('netstat output accepted')
        # check if ip forwarding enabled
        cat_out, cat_err = shell('cat /proc/sys/net/ipv4/ip_forward')
        if cat_err is None:  # WTF
            log.error('cat not responding')
            return False
        if b'Permission denied' in cat_err:
            log.error('Insufficient permissions to check /proc/sys/net/ipv4/ip_forward')
            return False
        if b'1' not in cat_out:
            log.error('IP forwarding disabled. Enable it with `echo "1" > /proc/sys/net/ipv4/ip_forward`')
            return False
        log.debug('ip forwarding enabled')

    log.debug('Current platform is supported')
    return True

#######################
## PLATFORM SPECIFIC ##
#######################

@platform_specific('Linux')
def get_rule(from_port, to_port):
    ''' Get rule tuple from firewall rules dump
        
    Parameters:
        from_port (int): port which traffic will be forwarded
        to_port (int): port traffic will be forwarded to

    Returns:
        (int, int, str, Any): rule tuple (from_port, to_port, source addr, rules)

    '''
    cmd = 'iptables-save'
    log.debug('Executing `%s`' % cmd)
    out, err = shell(cmd)
    if err is None:
        log.error('iptables-save not responding')
        return None
    elif len(err) > 2:
        log.error('IPTABLES-SAVE ERROR:')
        log.error(err)
    if out is not None and len(out) < 3:
        log.error('bad response from iptables-save')
        log.error('IPTABLES-SAVE OUTPUT:')
        log.error(out)
        return None
    # extract NAt table (from *nat line till COMMIT line)
    try:
        dump = out.decode('utf-8')
        rule_lines = dump[dump.index('*nat'):]
        rule_lines = dump[:dump.index('COMMIT')].splitlines()
    except UnicodeDecodeError:
        log.error('Cannot decode iptables-save output')
        log.error('IPTABLES-SAVE OUTPUT:')
        log.error(out)
        return None
    except ValueError:
        log.error('Cannot find NAT table in iptables-save output')
        log.error('IPTABLES-SAVE OUTPUT:')
        log.error(out)
        return None
    # resulting variables (iport, oport, oaddr, rules)
    iport, oport, oaddr, rules = None, None, '127.0.0.1', []
    # filter NAT table
    for line in rule_lines:
        if ('--dport %d' % from_port) in line and ('--to-ports %d' % to_port) in line and '-s 127.0.0.1' in line:
            rules.append(line)
    # return found rules
    log.debug('Get rule for [%d, %d]: %s' % (from_port, to_port, str(rules)))
    if len(rules) > 1:
        iport = int(re.search(r'--dport (\d+)', rules[0]).group(1))
        oport = int(re.search(r'--to-ports (\d+)', rules[0]).group(1))
        return (iport, oport, oaddr, rules)

    return None

@platform_specific('Windows')
def get_rule(from_port, to_port):
    ''' Get rule tuple from firewall rules dump
        
    Parameters:
        from_port (int): port which traffic will be forwarded
        to_port (int): port traffic will be forwarded to

    Returns:
        (int, int, str, Any): rule tuple (from_port, to_port, source addr, rules)

    '''
    cmd = 'netsh interface portproxy dump'
    log.debug('Executing `%s`' % cmd)
    out, err = shell(cmd)
    if err is None:
        log.error('netsh not responding')
        return None
    elif len(err) > 2:
        log.error('NETSH ERROR:')
        log.error(err)
    if out is not None and len(out) < 3:
        log.error('bad response from netsh')
        log.error('NETSH OUTPUT:')
        log.error(out)
        return None
    # extract portproxy rules (from reset line till popd line)
    try:
        dump = out.decode('utf-8')
        rule_lines = dump[dump.index('reset'):dump.index('popd')].splitlines()
    except UnicodeDecodeError:
        log.error('Cannot decode netsh output')
        log.error('NETSH OUTPUT:')
        log.error(out)
        return None
    except ValueError:
        log.error('Cannot find rules in portproxy dump')
        log.error('NETSH OUTPUT:')
        log.error(out)
        return None
    # find rule
    for line in rule_lines:
        if ('listenport=%d' % from_port) in line and ('connectport=%d' % to_port):
            log.debug('Get rule for [%d, %d]: "%s"' % (from_port, to_port, line))
            iport = int(re.search(r'listenport=(\d+)', line).group(1))
            oport = int(re.search(r'connectport=(\d+)', line).group(1))
            oaddr = re.search(r'connectaddress=([0-9.]+)', line).group(1)
            return (iport, oport, oaddr, line)

    return None

@platform_specific('Linux')
def add_rule(from_port, to_port):
    ''' Add port forwarding rule
        
    Parameters:
        from_port (int): port which traffic will be forwarded
        to_port (int): port traffic will be forwarded to

    '''
    cmd = 'iptables -t nat -A PREROUTING -s 127.0.0.1 -p tcp --dport %d -j REDIRECT --to %d'
    log.debug('Executing `%s`' % cmd)
    out, err = shell(cmd % (from_port, to_port))
    if err is None:
        log.error('iptables not responding')
        return
    elif len(err) > 2:
        log.error('IPTABLES ERROR:')
        log.error(err)
    if out is not None and len(out) > 2:
        log.warning('IPTABLES OUTPUT:')
        log.warning(err)
        
    cmd = 'iptables -t nat -A OUTPUT -s 127.0.0.1 -p tcp --dport %d -j REDIRECT --to %d'
    log.debug('Executing `%s`' % cmd)
    out, err = shell(cmd % (from_port, to_port))
    if err is None:
        log.error('iptables not responding')
        return
    elif len(err) > 2:
        log.error('IPTABLES ERROR:')
        log.error(err)
    if out is not None and len(out) > 2:
        log.warning('IPTABLES OUTPUT:')
        log.warning(err)

@platform_specific('Windows')
def add_rule(from_port, to_port):
    ''' Add port forwarding rule
        
    Parameters:
        from_port (int): port which traffic will be forwarded
        to_port (int): port traffic will be forwarded to

    '''
    cmd = 'netsh interface portproxy add v4tov4 listenport=%d listenaddress=0.0.0.0 connectport=%d connectaddress=127.0.0.1'
    log.debug('Executing `%s`' % cmd)
    out, err = shell(cmd % (from_port, to_port))
    if err is None:
        log.error('netsh not responding')
        return
    elif len(err) > 2:
        log.error('NETSH ERROR:')
        log.error(err)
    if out is not None and len(out) > 4:
        log.warning('NETSH OUTPUT:')
        log.warning(err)

@platform_specific('Linux')
def drop_rule(rule):
    ''' Drop port forwarding rule
        
    Parameters:
        from_port (rule_tuple): rule which will be dropped from NAT table

    '''
    cmd = 'iptables -t nat -D PREROUTING -s 127.0.0.1 -p tcp --dport %d -j REDIRECT --to %d'
    log.debug('Executing `%s`' % cmd)
    out, err = shell(cmd % (rule[0], rule[1]))
    if err is None:
        log.error('iptables not responding')
        return
    elif len(err) > 2:
        log.error('IPTABLES ERROR:')
        log.error(err)
    if out is not None and len(out) > 2:
        log.warning('IPTABLES OUTPUT:')
        log.warning(err)
        
    cmd = 'iptables -t nat -D OUTPUT -s 127.0.0.1 -p tcp --dport %d -j REDIRECT --to %d'
    out, err = shell(cmd % (rule[0], rule[1]))
    if err is None:
        log.error('iptables not responding')
        return
    elif len(err) > 2:
        log.error('IPTABLES ERROR:')
        log.error(err)
    if out is not None and len(out) > 2:
        log.warning('IPTABLES OUTPUT:')
        log.warning(err)

@platform_specific('Windows')
def drop_rule(rule):
    ''' Drop port forwarding rule
        
    Parameters:
        from_port (rule_tuple): rule which will be dropped from NAT table

    '''
    cmd = 'netsh interface portproxy delete v4tov4 listenport=%d listenaddress=0.0.0.0'
    log.debug('Executing `%s`' % cmd)
    out, err = shell(cmd % (rule[0]))
    if err is None:
        log.error('netsh not responding')
        return
    elif len(err) > 2:
        log.error('NETSH ERROR:')
        log.error(err)
    if out is not None and len(out) > 4:
        log.warning('NETSH OUTPUT:')
        log.warning(err)

@platform_specific('Linux')
def get_listening_ports(pid):
    ''' Get listening ports of specified process
        
    Parameters:
        pid (int): process PID

    Returns:
        list: list of listening ports

    '''
    cmd = 'netstat -nltp'
    out, err = shell(cmd)
    if err is None:
        log.error('netstat not responding')
        return
    elif len(err) > 2:
        log.error('NETSTAT ERROR:')
        log.error(err)
    if out is not None and len(out) < 3:
        log.error('bad response from netstat')
        log.error('NETSTAT OUTPUT:')
        log.error(out)
        return None
    ports = set()
    try:
        lines = out.decode('utf-8').splitlines()
    except UnicodeDecodeError:
        log.error('Cannot decode netstat output')
        log.error('NETSTAT OUTPUT:')
        log.error(out)
        return None
    # parse netstat ouput
    for line in lines:
        if 'tcp' not in line or 'LISTEN' not in line:
            continue
        # parse netstat line as table row
        row = [x for x in line.split(' ') if x]
        if row[-1].split('/')[0] == str(pid): # last column is PID/ProcessName
            ports.add(int(row[3].split(':')[-1])) # fourth column is addr:port
    return list(ports)

@platform_specific('Windows')
def get_listening_ports(pid):
    ''' Get listening ports of specified process
        
    Parameters:
        pid (int): process PID

    Returns:
        list: list of listening ports

    '''
    cmd = 'netstat.exe -ano'
    out, err = shell(cmd, timeout=2)
    if err is None:
        log.error('netstat not responding')
        return
    elif len(err) > 2:
        log.error('NETSTAT ERROR:')
        log.error(err)
    if out is not None and len(out) < 3:
        log.error('bad response from netstat')
        log.error('NETSTAT OUTPUT:')
        log.error(out)
        return None
    ports = set()
    try:
        lines = out.decode('utf-8').splitlines()
    except UnicodeDecodeError:
        log.error('Cannot decode netstat output')
        log.error('NETSTAT OUTPUT:')
        log.error(out)
        return None
    # parse netstat ouput
    for line in lines:
        if 'TCP' not in line or 'LISTENING' not in line:
            continue
        # parse netstat line as table row
        row = [x for x in line.split(' ') if x]
        if row[-1] == str(pid): # last column is PID
            ports.add(int(row[1].split(':')[-1])) # second column is addr:port
    return list(ports)

def get_game_processes():
    ''' Get running game instances (includes netcat instances if INCLUDE_NETCAT flag enabled)

    Returns:
        list: list of PIDs of running game instances

    '''
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
        except (OSError, psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    
    return games


#############################
## MINE PORT PROXY MANAGER ##
#############################

class MinePortProxy(object):
    ''' Port Proxy Manager

        Workflow loop:
            * filter_old_instances
            * load_new_instances
            * sleep timeout

        Expects close method call to drop all added firewall rules
    '''
    def __init__(self, port_start=25565, port_end=None):
        ''' MinePortProxy Constructor
            
        Parameters:
            port_start (int): port pool minimum value (default: 25565)
            port_end (int): port pool maximum value (default: port_end)

        '''
        super().__init__()

        if port_end is None:
            port_end = port_start

        self.instances = []
        self.pids = []

        self.port_pool = set(range(port_start, port_end+1))

    def filter_old_instances(self):
        ''' Drops rules for non-existent listening ports associated with game instances '''
        live_instances = []
        live_pids = []

        for pid, rule in self.instances:
            for _ in range(4):
                ports = get_listening_ports(pid)
                if ports is not None:
                    break
            if ports is None:
                log.warning('Can not get listening ports for PID %d' % pid)
                log.warning('Keeping rule (%d -> %d) alive' % (rule[0], rule[1]))
                live_instances.append((pid, rule))
                live_pids.append(pid)
                continue
            if len(ports) == 0 or ports[0] != rule[1]: # assume that instance listens only one port
                drop_rule(rule)
                self.port_pool.add(rule[0])
                log.info('Old instance (pid %d) dropped (rule %d -> %d)' % (pid, rule[0], rule[1]))
            else:
                #log.debug('Instance (pid %d) alive (rule %d -> %d)' % (pid, rule[0], rule[1]))
                live_instances.append((pid, rule))
                live_pids.append(pid)
        
        self.instances = live_instances
        self.pids = live_pids

    def load_new_instances(self):
        ''' Create missing rules for listening ports associated with game instances '''
        for game in get_game_processes():
            pid = game['pid']
            if pid in self.pids:
                continue
            ports = get_listening_ports(pid)
            if ports is None:
                log.warning('Can not get listening ports for PID %d' % pid)
                continue
            if len(ports) == 0:
                continue
            if len(self.port_pool) == 0:
                log.info('Cannot load new instance (pid %d), not enough ports' % pid)
                continue
            from_port = self.port_pool.pop()
            to_port = ports[0] # assume that instance listens only one port
            add_rule(from_port, to_port)
            rule = get_rule(from_port, to_port)
            if rule is None:
                log.error('Failed to add rule %d -> %d' % (from_port, to_port))
                self.port_pool.add(from_port)
                continue
            self.instances.append((pid, rule))
            self.pids.append(pid)
            log.info('New instance (pid %d) added (rule %d -> %d)' % (pid, rule[0], rule[1]))

    def close(self):
        ''' Drops all created rules '''
        for _, rule in self.instances:
            drop_rule(rule)
            self.port_pool.add(rule[0])
        self.instances = []
        self.pids = []

class MinePortProxyThreaded(MinePortProxy):
    ''' Threaded Manager extends Proxy Manager with threaded start/stop functionality '''
    def __init__(self, *args):
        ''' MinePortProxyThreaded Constructor
            
        Parameters:
            port_start (int): port pool minimum value (default: 25565)
            port_end (int): port pool maximum value (default: port_end)

        '''
        super().__init__(*args)

        self.thread = threading.Thread(target=self.__thread_loop, args=())
        self.stop_event = threading.Event()
        self.started = False

    def __thread_loop(self):
        while not self.stop_event.is_set():
            self.filter_old_instances()
            self.load_new_instances()
            time.sleep(1)
        self.close()

    def start(self):
        ''' Starts manager in seperate thread '''
        if self.started == True:
            raise Exception('MinePortProxyDaemon already started')
        self.started = True
        self.thread.start()

    def stop(self):
        ''' Stops manager '''
        if self.started == False:
            raise Exception('MinePortProxyDaemon is not started')
        self.stop_event.set()
        self.thread.join()
        self.started = False
        self.stop_event.clear()

def set_log_level(lvl):
    LOGGING_CONFIG['handlers']['default']['level'] = lvl
    LOGGING_CONFIG['loggers']['mineportproxy']['level'] = lvl

def main(argv):
    parser = argparse.ArgumentParser(description='Starts MinePortProxy manager')
    parser.add_argument('-d', '--debug', action='store_true', help='enables debug output and INCLUDE_NETCAT flag')
    parser.add_argument('-l', '--log-level', nargs=1, default=['INFO'], help='sets log level')
    parser.add_argument('port_start', nargs='?', type=int, default=25565, help='port pool minimum value')
    parser.add_argument('port_end', nargs='?', type=int, default=None, help='port pool maximum value')
    args = parser.parse_args(argv[1:])

    if args.log_level[0] not in ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']:
        print('Bad log level argument')
        parser.print_help()
        return - 1
    set_log_level(args.log_level[0])

    if args.debug:
        set_log_level('DEBUG')
        global INCLUDE_NETCAT
        INCLUDE_NETCAT = True

    port_start = args.port_start
    port_end = port_start

    if args.port_end is not None:
        port_end = args.port_end

    if port_start > port_end or port_start < 1 or port_end > 65534:
        print('Invalid port range')
        parser.print_help()
        return - 1

    # ARGUMENT PARSING ENDS HERE

    global log
    logging.config.dictConfig(LOGGING_CONFIG)
    log = logging.getLogger('mineportproxy')
            
    if check_platform_support() is False:
        log.critical('Platform check failed')
        input('Press any key to exit')
        return - 1

    manager = MinePortProxyThreaded(port_start, port_end)
    log.info('Starting MinePortProxy manager')
    manager.start()

    def signal_handler(sig, frame):
        log.info('Stopping MinePortProxy manager')
        manager.stop()
        sys.exit(sig)

    signal.signal(signal.SIGINT, signal_handler)

    while True:
        try:
            inp = input()
            if inp == 'quit' or inp == 'q':
                break
        except KeyboardInterrupt:
            break

    return 0

bind_platform_funcs()
if __name__ == '__main__':
    res = main(sys.argv)
    sys.exit(res)
