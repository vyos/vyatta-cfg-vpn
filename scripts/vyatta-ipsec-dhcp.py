#!/usr/bin/env python3
#
# Copyright (C) 2019 VyOS maintainers and contributors
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 or later as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#

import os
import re
import sys
import subprocess
import argparse
import syslog
import time
import vici

import vyos.config

config_file = "/etc/ipsec.conf";
secrets_file = "/etc/ipsec.secrets";


def parse_cli_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--interface", type=str)
    parser.add_argument("--new_ip", type=str)
    parser.add_argument("--old_ip", type=str)
    parser.add_argument("--reason", type=str)
    args = parser.parse_args()
    return args


def ipsec_conf_r():
    header = ''
    footer = ''
    finheader = 0
    connlist = list()
    conndict = dict()
    curconn = ''

    with open(config_file) as f:
        for line in f:
            if re.search('^\s*$', line) and finheader:
                continue
            if re.search('\#conn.*', line):
                curconn = ''
                continue
            if re.search('(peer-.*-tunnel.*)', line):
                finheader = 1
                connid = re.search(r'(peer-.*-tunnel.*)', line).group(1)
                curconn = connid
                if connid not in connlist:
                    conndict[connid] = dict()
                    conndict[connid]['_dhcp_iface'] = None
                    conndict[connid]['_lip'] = None
                    conndict[connid]['_lines'] = list()
            elif re.search('dhcp-interface=(.*)', line) and curconn != '':
                conndict[connid]['_dhcp_iface'] = re.search(r'dhcp-interface=(.*)', line).group(1)
            elif re.search('left=(.*)', line) and curconn != '':
                conndict[connid]['_lip'] = re.search(r'left=(.*)', line).group(1)
            elif not finheader:
                header = header + line
            elif curconn != '':
                conndict[connid]['_lines'].append(line)
            elif curconn == '':
                footer = footer + line;
        connlist.append(conndict)
    return connlist, header, footer


def ipsec_conf_w(connlist, header, footer, interface, new_ip):
    try:
        with open(config_file, 'w') as f:
            f.write('{0}\n'.format(header))
            for connid in connlist:
                connname = next(iter(connid))
                f.write('conn {0}\n'.format(connname))
                if connid[connname]['_dhcp_iface']:
                    if connid[connname]['_dhcp_iface'] == interface:
                        if not new_ip:
                            new_ip = ''
                        connid[connname]['_lip'] = new_ip
                    f.write('\t#dhcp-interface={0}\n'.format(connid[connname]['_dhcp_iface']))
                f.write('\tleft={0}\n'.format(connid[connname]['_lip']))
                for line in connid[connname]['_lines']:
                    f.write('{0}'.format(line))
                f.write('#conn {0}\n\n'.format(connname))
            f.write('{0}\n'.format(footer))
    except EnvironmentError as e:
        sys.exit('Can\'t open {0}: {1}'.format(config_file, e))


def ipsec_sec_r():
    lines = []

    with open(secrets_file) as f:
        lines = [line for line in f]
    return lines


def ipsec_sec_w(lines, interface, new_ip):
    try:
        with open(secrets_file, 'w') as f:
            for line in lines:
                if re.search('(.*)\#dhcp-interface=(.*)\#', line) and \
                   re.search('(.*)\#dhcp-interface=(.*)\#', line).group(2) == interface:
                    secretline = re.search('(.*)\#dhcp-interface=(.*)\#', line).group(1)
                    if not new_ip:
                        new_ip = "#"
                    secline = re.search('(.*?) (.*?) : PSK (.*?) #dhcp', line)
                    line = '{0} {1} : PSK {2} #dhcp-interface={3}#\n'.format(new_ip,
                                      secline.group(2), secline.group(3), interface)
                f.write('{0}'.format(line))
    except EnvironmentError as e:
        sys.exit('Can\'t open {0}: {1}'.format(config_file, e))


def conn_list():
    v = vici.Session()
    config = vyos.config.Config()
    config_conns = config.list_effective_nodes("vpn ipsec site-to-site peer")
    connup = []


    v = vici.Session()
    for conn in v.list_sas():
        for key in conn:
            for c_conn in config_conns:
                if c_conn in key:
                    if config.return_effective_value("vpn ipsec site-to-site peer {0} dhcp-interface".format(c_conn)):
                        connup.append(key)
    
    return connup


def run(*popenargs, input=None, check=False, **kwargs):
    if input is not None:
        if 'stdin' in kwargs:
            raise ValueError('stdin and input arguments may not both be used.')
        kwargs['stdin'] = subprocess.PIPE

    process = subprocess.Popen(*popenargs, **kwargs)
    try:
        stdout, stderr = process.communicate(input)
    except:
        process.kill()
        process.wait()
        raise
    retcode = process.poll()
    if check and retcode:
        raise subprocess.CalledProcessError(
            retcode, process.args, output=stdout, stderr=stderr)
    return retcode, stdout, stderr


def term_conn(active_conn):
    v = vici.Session()
    for conn in active_conn:
        try:
            list(v.terminate({"ike": conn, "force": "true"}))
        except:
            pass


def reload_conn():
    run(["/usr/sbin/ipsec", "rereadall"], stderr=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL)
    run(["/usr/sbin/ipsec", "update"], stderr=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL)


def init_conn(active_conn, updated_conn):
    v = vici.Session()
    for conn in active_conn:
        if conn not in updated_conn:
            list(v.initiate({"child": conn, "timeout": "10000"}))


def main():
    args = parse_cli_args()
    syslog.openlog('ipsec-dhclient-hook')
    
    syslog.syslog(syslog.LOG_NOTICE, 'Receive DHCP address updated to {0} from {1}'
           ', reason: {2}.'.format(args.new_ip, args.old_ip, args.reason))

    if args.old_ip == args.new_ip and args.reason != 'BOUND' or args.reason == 'REBOOT' or args.reason == 'EXPIRE': 
        syslog.syslog(syslog.LOG_NOTICE, 'No ipsec update needed.')
        sys.exit(0)

    syslog.syslog(syslog.LOG_NOTICE, 'DHCP address updated to {0} from {1}: '
          ' Updating ipsec configuration, reason: {2}.'.format(args.new_ip, args.old_ip, args.reason))

    connlist, header, footer = ipsec_conf_r()
    ipsec_conf_w(connlist, header, footer, args.interface, args.new_ip)

    lines = ipsec_sec_r()
    ipsec_sec_w(lines, args.interface, args.new_ip)

    if args.new_ip:
        active_conn = conn_list()
        term_conn(active_conn)
        reload_conn()
        time.sleep(5)
        updated_conn = conn_list()
        init_conn(active_conn, updated_conn)
    

if __name__ == '__main__':
    main()
