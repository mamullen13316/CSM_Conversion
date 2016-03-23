'''
This script will parse a CSM configuration and generate equivalent Citrix Netscaler command line configuration.

The optional argument -oper can be used to specify a file that contains the output of 'show mod csm all vservers | OPER'.
The script will parse this file and build the vserver_dict keys from that instead of from the source
configuration.  This can be used to ensure that only active VIPs are migrated.

An SSL module configuration can also be optionally provided using the -ssl_file argument.  The script will examine the
SSL configuration and modify the VIP -> real mapping as necessary to build the Netscaler configuration
'''


import os
import re
import argparse
import time

parser = argparse.ArgumentParser(description='Cisco CSM Configuration Parser')
parser.add_argument('-config_file', help='Specify a configuration file to parse', required=True)
parser.add_argument('-output_file', help='Specify an output file', required=True)
parser.add_argument('-oper_file',help='Specify a file with the output of the command "show mod csm all vservers | i OPER"',required=False)
parser.add_argument('-ssl_file',help='Specify an SSL module configuration',required=False)
parser.add_argument('-oper_reals',help='Specify a file with the output of the command "show mod csm all reals | i OPER',required=False)
args = parser.parse_args()

fn = args.config_file
ofn = args.output_file
oper_file = args.oper_file
ssl_file = args.ssl_file
oper_reals = args.oper_reals

vserver_dict = {}
slb_policy_dict = {}
serverfarm_dict = {}
ssl_dict = {}

found = False

def printandwrite(print_string, output_file):
    print(print_string)
    if os.path.isfile(output_file):
        with open(output_file,'a') as openfile:
            openfile.write(print_string + '\n')
    else:
        with open(output_file,'w') as openfile:
            openfile.write(print_string + '\n')


print ('Running.  This may take a while.')

# If the operational VIPs are specified, build the keys from that. Otherwise, build them from the running config.
# vserver name will be the key to vserver_dict
if oper_file:
    with open(oper_file,'r') as f:
        l = f.readlines()
    for line in l:
        k = line[0:line.find(' ')]
        vserver_dict[k] = {}
    with open(fn,'r') as f:
        l = f.readlines()
else:
    with open(fn,'r') as f:
        l = f.readlines()
    for line in l:
        lines = line.strip()
        m = re.search('^vserver', lines)
        if m:
            x, k = lines.split(' ')
            vserver_dict[k] = {}

for key in vserver_dict.keys():
    for line in l:
        m = re.search('vserver {0}$'.format(key), line.rstrip())
        if m:
            found = True
        if found and 'virtual' in line:
            ln = line.strip().split(' ')
            if len(ln) == 3:
                v, vip, port = line.strip().split(' ')
            if len(ln) == 4:
                v, vip, proto, port = line.strip().split(' ')
            if len(ln) == 6:
                v, vip, proto, port, serv, svc = line.strip().split(' ')
            vserver_dict[key]['virtual'] = vip
            vserver_dict[key]['port'] = port
            vserver_dict[key]['proto'] = proto
        if found and 'slb-policy' in line:
            x, slb_policy = line.strip().split(' ')
            vserver_dict[key]['slb-policy'] = slb_policy
            slb_policy_dict[slb_policy] = {}
        m = re.search('^  serverfarm', line)
        if found and m:
            x, slb_policy = line.strip().split(' ')
            vserver_dict[key]['slb-policy'] = slb_policy
            slb_policy_dict[slb_policy] = {'serverfarm':slb_policy}
            serverfarm_dict[slb_policy] = {}
        if found and '!' in line:
            found = False
            break

for key in slb_policy_dict.keys():
    for line in l:
        m = re.search('^ policy {0}$'.format(key), line.rstrip())
        if m:
            found = True
        if found and 'serverfarm' in line:
            x, sf_name = line.strip().split()
            slb_policy_dict[key]['serverfarm'] = sf_name
            serverfarm_dict[sf_name] = {}
        if found and '!' in line:
            found = False
            break

for key in serverfarm_dict.keys():
    for line in l:
        m = re.search('^ serverfarm {0}$'.format(key),line.rstrip())
        if m:
            found = True
        if found and 'real' in line:
            port = ''
            ln = line.strip().split(' ')
            if len(ln) == 3:
                real, ip, port = line.strip().split(' ')
            if len(ln) == 2:
                real, ip = line.strip().split(' ')
            if 'real' in serverfarm_dict[key]:
                serverfarm_dict[key]['real'].append((ip,port))
            else:
                serverfarm_dict[key]['real'] = [(ip,port)]

        if found and 'relocation' in line:
            wh, r, url = line.strip().split(' ')
            serverfarm_dict[key]['redirect_url'] = url

        if found and 'probe' in line:
            ln = line.strip().split(' ')
            if len(ln) == 3:
                p, probe, pproto = line.strip().split(' ')
            if len(ln) == 2:
                p, probe = line.strip().split(' ')
            try:
                serverfarm_dict[key]['probe'].append(probe)
            except KeyError:
                serverfarm_dict[key]['probe'] = [probe]

        if found and '!' in line:
            found = False
            break

if ssl_file:
    with open(ssl_file,'r') as f:
        l = f.readlines()

    for line in l:
        if 'ssl-proxy service' in line:
            print line
            x,y,name = line.strip().split()
            ssl_dict[name] = {}
        if 'virtual ipaddr' in line:
            v,i,ssl_vip,p,t,po,ssl_port = line.strip().split()
            ssl_dict[name]['ssl-vip'] = ssl_vip
            ssl_dict[name]['ssl-port'] = ssl_port
        if 'server ipaddr' in line:
            s,i,csm_vip,p,t,po,csm_port = line.strip().split()
            ssl_dict[name]['csm-vip'] = csm_vip
            ssl_dict[name]['csm-port'] = csm_port

    with open (fn,'r') as f:
        l = f.readlines()

    for ssl_key in ssl_dict.keys():
        if 'csm-vip' in ssl_dict[ssl_key] and 'ssl-vip' in ssl_dict[ssl_key]:
            current_sf = ''
            current_vserver = ''
            for line in l:
                m = re.search('^ serverfarm',line)
                if m:
                    t,current_sf = line.strip().split()
                m = re.search('^ vserver',line)
                if m:
                    t, current_vserver = line.strip().split()
                if 'real {0} {1}'.format(ssl_dict[ssl_key]['ssl-vip'],ssl_dict[ssl_key]['ssl-port']) in line:
                    ssl_dict[ssl_key]['src_serverfarm'] = current_sf
                if 'virtual {0} tcp {1}'.format(ssl_dict[ssl_key]['csm-vip'],ssl_dict[ssl_key]['csm-port']) in line:
                    ssl_dict[ssl_key]['dst_vserver'] = current_vserver

    for ssl_key in ssl_dict.keys():
        if 'src_serverfarm' in ssl_dict[ssl_key] and 'dst_vserver' in ssl_dict[ssl_key]:
            if ssl_dict[ssl_key]['src_serverfarm'] in serverfarm_dict and ssl_dict[ssl_key]['dst_vserver'] in serverfarm_dict:
                if 'real' in serverfarm_dict[ssl_dict[ssl_key]['src_serverfarm']] and 'real' in serverfarm_dict[ssl_dict[ssl_key]['dst_vserver']]:
                    serverfarm_dict[ssl_dict[ssl_key]['src_serverfarm']]['real'] = serverfarm_dict[ssl_dict[ssl_key]['dst_vserver']]['real']

    for ssl_key in ssl_dict.keys():
        if 'src_serverfarm' in ssl_dict[ssl_key] and 'dst_vserver' in ssl_dict[ssl_key]:
            if not ssl_dict[ssl_key]['dst_vserver'] in vserver_dict and ssl_dict[ssl_key]['src_serverfarm'] in vserver_dict:
                vserver_dict.pop(ssl_dict[ssl_key]['src_serverfarm'])
            if ssl_dict[ssl_key]['dst_vserver'] in vserver_dict:
                vserver_dict.pop(ssl_dict[ssl_key]['dst_vserver'])
        if 'src_serverfarm' in ssl_dict[ssl_key] and not 'dst_vserver' in ssl_dict[ssl_key]:
            if ssl_dict[ssl_key]['src_serverfarm'] in vserver_dict:
                vserver_dict.pop(ssl_dict[ssl_key]['src_serverfarm'])
                

if oper_reals:
    with open(oper_reals,'r') as f:
        l = f.readlines()

    oper_real_list = []

    for line in l:
        ip = line[0:line.find(':')]
        port = line[line.find(':'):line.find(' ')].strip(':')
        oper_real_list.append((ip,port))

    for key in serverfarm_dict.keys():
        if 'real' in serverfarm_dict[key]:
            for i in xrange(len(serverfarm_dict[key]['real']) - 1,-1,-1):
                element = serverfarm_dict[key]['real'][i]
                if not element in oper_real_list:
                    del serverfarm_dict[key]['real'][i]

# Begin printing output
printandwrite ('-'*20 + time.ctime() + '-'*20,ofn)

for key in vserver_dict.keys():
    redirect_url = ''
    rserver_port = ''
    monitor_proto = ''
    vserver_name = key
    if 'virtual' in vserver_dict[key]:
        vserver_ip = vserver_dict[key]['virtual']
    else:
        continue
    vserver_port = vserver_dict[key]['port']
    vserver_proto = 'TCP'
    if vserver_port == 'www':
        vserver_proto = 'HTTP'
        vserver_port = '80'
    if vserver_port == 'https':
        vserver_proto = 'SSL'
        vserver_port = '443'

    if 'slb-policy' in vserver_dict[key]:
        if 'serverfarm' in slb_policy_dict[vserver_dict[key]['slb-policy']]:
            service_group =  slb_policy_dict[vserver_dict[key]['slb-policy']]['serverfarm']
        else:
            continue
        if 'real' in serverfarm_dict[slb_policy_dict[vserver_dict[key]['slb-policy']]['serverfarm']]:
            rserver_list = serverfarm_dict[slb_policy_dict[vserver_dict[key]['slb-policy']]['serverfarm']]['real']
            if len(rserver_list) > 0:
                rserver_port = rserver_list[0][1]
        else:
            rserver_list = []
        if 'probe' in serverfarm_dict[slb_policy_dict[vserver_dict[key]['slb-policy']]['serverfarm']]:
            monitor_proto = serverfarm_dict[slb_policy_dict[vserver_dict[key]['slb-policy']]['serverfarm']]['probe']
            if len(monitor_proto) == 1:
                monitor_proto = monitor_proto[0]
            if len(monitor_proto) == 2:
                monitor_proto = monitor_proto[1]
            
        if 'redirect_url' in serverfarm_dict[slb_policy_dict[vserver_dict[key]['slb-policy']]['serverfarm']]:
            redirect_url = serverfarm_dict[slb_policy_dict[vserver_dict[key]['slb-policy']]['serverfarm']]['redirect_url']
            responder_policy = key + '_REDIRECT_POLICY'
            responder_action = key + '_REDIRECT_ACTION'
            if not 'http' in redirect_url:
                redirect_url = 'https://' + redirect_url
    else:
        continue

    if vserver_port == '443' and rserver_port == '443':
        vserver_proto = 'SSL_BRIDGE'

    if vserver_port == '443':
        persist_type = 'SSLSESSION'
    else:
        persist_type = 'SOURCEIP'


    printandwrite('add ns ip {0} 255.255.255.255 -type VIP -mgmtAccess ENABLED -state DISABLED'.format(vserver_ip),ofn)
    printandwrite('add lb vserver {0} {1} {2} {3} -persistenceType {4}'.format(vserver_name,vserver_proto,vserver_ip,vserver_port,persist_type),ofn)

    if redirect_url:
        if '%p' in redirect_url:
            redirect_url = redirect_url.strip('%p')
            printandwrite('add responder action {0} redirect "\\"{1}\\" + HTTP.REQ.URL.PATH_AND_QUERY.HTTP_URL_SAFE"'.format(responder_action,redirect_url),ofn)
        else:
            printandwrite('add responder action {0} redirect "\\"{1}\\""'.format(responder_action,redirect_url),ofn)
        printandwrite('add responder policy {0} HTTP.REQ.IS_VALID {1}'.format(responder_policy,responder_action),ofn)
        printandwrite('bind lb vserver {0} -PolicyName {1} -priority 100 -gotoPriorityExpression END -type REQUEST'.format(vserver_name,responder_policy),ofn)
        printandwrite('bind lb vserver {0} always_up_service_{1}'.format(vserver_name,vserver_port),ofn)
    else:
        if vserver_port == '443' and not rserver_port == '443':
            service_group_proto = 'HTTP'
            service_group = service_group + '_{0}'.format(rserver_port)
        else:
            service_group_proto = vserver_proto
        printandwrite('add serviceGroup {0} {1} -usip YES'.format(service_group,service_group_proto),ofn)
        printandwrite('bind lb vserver {0} {1}'.format(vserver_name,service_group),ofn)

        i = 0
        for item in rserver_list:
            i += 1
            real_ip = item[0]
            real_port = item[1]
#            real_name = slb_policy_dict[vserver_dict[key]['slb-policy']]['serverfarm'] + "_{0}".format(str(i))
            real_name = 'REAL-' + real_ip
            printandwrite('add server {0} {1}'.format(real_name,real_ip),ofn)
            printandwrite('bind serviceGroup {0} {1} {2}'.format(service_group,real_name,real_port),ofn)

##            monitor_proto = vserver_proto.lower()
##
##            if vserver_proto == 'SSL' and not real_port == '443':
##                monitor_proto = 'http'
##
##            if vserver_proto == 'SSL' and real_port == '443':
##                monitor_proto = 'https'
##
##            if vserver_proto == 'SSL_BRIDGE':
##                monitor_proto = 'https'
        
##        if 'TCP' in monitor_proto:
##            monitor_proto = 'tcp'
        
        if 'SSLPROBE' in monitor_proto:
            monitor_proto = 'https'
        if monitor_proto == 'TCP':
            monitor_proto = monitor_proto.lower()
        if not monitor_proto:
            monitor_proto = 'tcp'

        printandwrite('bind serviceGroup {0} -monitorName {1}'.format(service_group,monitor_proto),ofn)
        if monitor_proto == 'IPS_TCP_81':
            printandwrite('bind serviceGroup {0} -monitorName {1}'.format(service_group,'tcp'),ofn)
            

    printandwrite('\n',ofn)

output_set = set()
for key in vserver_dict.keys():
    if 'virtual' in vserver_dict[key]:
        vip = vserver_dict[key]['virtual']
        output_set.add(vip)

for vip in output_set:
    printandwrite('enable ns ip {0}'.format(vip),ofn)
