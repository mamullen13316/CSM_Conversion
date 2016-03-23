import os
import re
import argparse

parser = argparse.ArgumentParser(description='Cisco CSM Configuration Parser')
parser.add_argument('-config_file', help='Specify a configuration file to parse', required='True')
parser.add_argument('-output_file', help='Specify an output file', required='True')
args = parser.parse_args()

fn = args.config_file
ofn = args.output_file

f = open(fn)
l = f.readlines()
f.close()

server_dict = {}
found = False

for line in l:
    lines = line.strip()
    m = re.search('^vserver', lines)
    if m:
        x, k = lines.split(' ')
        server_dict[k] = {}

for key in server_dict.keys():
    for line in l:
        m = re.search(key, line)
        if m:
            found = True
        if found and 'real' in line:
            ln = line.strip().split(' ')
            if len(ln) == 3:
                real, ip, port = line.strip().split(' ')
            if len(ln) == 2:
                real, ip = line.strip().split(' ')
            try:
                server_dict[key]['real'].append(ip)
            except KeyError:
                server_dict[key]['real'] = [ip]

        if found and 'virtual' in line:
            ln = line.strip().split(' ')
            if len(ln) == 3:
                v, vip, proto = line.strip().split(' ')
            if len(ln) == 4:
                v, vip, p, proto = line.strip().split(' ')
            if len(ln) == 6:
                v, vip, p, proto, serv, svc = line.strip().split(' ')
            server_dict[key]['virtual'] = vip
            server_dict[key]['proto'] = proto

        if found and 'relocation' in line:
            wh, r, url = line.strip().split(' ')
            server_dict[key]['redirect_url'] = url

        if found and 'probe' in line:
            ln = line.strip().split(' ')
            if len(ln) == 3:
                p, probe, pproto = line.strip().split(' ')
            if len(ln) == 2:
                p, probe = line.strip().split(' ')
            try:
                server_dict[key]['probe'].append(probe)
            except KeyError:
                server_dict[key]['probe'] = [probe]

        if '!' in line:
            found = False

for key in server_dict.keys():
    if 'virtual' in server_dict[key] and 'proto' in server_dict[key]:
        print ('vserver {0} {1} {2}'.format(key,server_dict[key]['virtual'],server_dict[key]['proto']))
    else:
        if 'virtual' in server_dict[key]:
            print ('vserver {0} {1}'.format(key,server_dict[key]['virtual']))
    i = 0
    if 'real' in server_dict[key]:
        for server in server_dict[key]['real']:
            i += 1
            print ('rserver {0}_{1} {2}'.format(key,i,server))
    print ('\n')


'''    print ('\nSERVERFARM: {0}'.format(key))

    try:
        print ('VIP: {0}'.format(server_dict[key]['virtual']))
    except KeyError:
        continue
    print ('PROTOCOL: {0}'.format(server_dict[key]['proto']))
    print ('SERVERS:')

    try:
        for item in server_dict[key]['real']:
            print (item)
    except KeyError:
        continue
'''

f = open(ofn, 'w')

print_list = []
for key in server_dict.keys():
    s = '{0} ;'.format(key)
    try:
        s = s + '{0} ;'.format(server_dict[key]['virtual'])
    except KeyError:
        continue
    s = s + '{0} ;'.format(server_dict[key]['proto'])
    try:
        real_list = server_dict[key]['real']
        for i in range(0, len(real_list)):
            if i == len(real_list) - 1:
                s = s + '{0} ;'.format(real_list[i])
            else:
                s = s + '{0} '.format(real_list[i])
    except KeyError:
        s += ';'

    try:
        probe_list = server_dict[key]['probe']
        for i in range(0, len(probe_list)):
            if i == len(probe_list) - 1:
                s = s + '{0} ;'.format(probe_list[i])
            else:
                s = s + '{0} '.format(probe_list[i])
    except KeyError:
        s += ';'

    try:
        s = s + '{0} \n'.format(server_dict[key]['redirect_url'])
    except KeyError:
        s += '\n'

    print_list.append(s)

for line in print_list:
    f.write(line)
f.close()
