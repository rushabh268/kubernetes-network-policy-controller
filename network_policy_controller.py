from kubernetes import client, config, watch
import kubernetes
import time
from tornado.ioloop import IOLoop
from tornado import gen
import pika
import sys

def send_policy_to_node(node_name, iptables):    
    #To-Do: Add check for rabbitmq status before sending the message
    connection = pika.BlockingConnection(pika.ConnectionParameters(host='localhost'))
    channel = connection.channel()
    channel.exchange_declare(exchange='topic_logs', exchange_type='topic')
    routing_key = node_name if node_name != None else 'iptables.info'
    message = ''.join(iptables) or 'No action!'
    channel.basic_publish(exchange='topic_logs', routing_key=routing_key, body=message)
    print(" [x] Sent %r:%r" % (routing_key, message))
    connection.close()

def create_new_policy_rules(network_policy, uid, callback):
    print 'Checking policy contents to add iptables based rules'
    policy_info = {}
    if 'metadata' in network_policy[uid]:
        if 'namespace' in network_policy[uid]['metadata']:
            policy_info['namespace'] = network_policy[uid]['metadata']['namespace']

    #Determing default deny or default allow policies for Ingress and Egress
    if 'spec' in network_policy[uid]:
        if 'policyTypes' in network_policy[uid]['spec']:
            if len(network_policy[uid]['spec']['policyTypes']) == 2:
                if network_policy[uid]['spec']['policyTypes'] == ['Ingress', "Egress"]:
                    if 'podSelector' in network_policy[uid]['spec']:
                        if network_policy[uid]['spec']['podSelector'] == {}:
                            policy_info['policy_type'] = 'default_deny_for_ingress_and_egress'
                        else:
                            policy_info['policy_type'] = 'network_policy'
            elif len(network_policy[uid]['spec']['policyTypes']) == 1:
                 if network_policy[uid]['spec']['policyTypes'] == 'Ingress':
                     if 'podSelector' in network_policy[uid]['spec']:
                         if network_policy[uid]['spec']['podSelector'] == {}:
                             policy_info['policy_type'] = 'default_deny_for_ingress'
                         else:
                             policy_info['policy_type'] = 'network_policy'
                 elif network_policy[uid]['spec']['policyTypes'] == 'Egress':
                     if 'podSelector' in network_policy[uid]['spec']:
                         if network_policy[uid]['spec']['podSelector'] == {}:
                             policy_info['policy_type'] = 'default_deny_for_egress'
                         else:
                             policy_info['policy_type'] = 'network_policy'
    else:
        if 'ingress' in network_policy[uid]['spec']:
            if network_policy[uid]['spec']['ingress'] == {}:
                if network_policy[uid]['spec']['podSelector'] == {}:
                    policy_info['policy_type'] = 'default_allow_for_ingress'
        elif 'egress' in network_policy[uid]['spec']:
            if network_policy[uid]['spec']['egress'] == {}:
                if network_policy[uid]['spec']['podSelector'] == {}:
                    policy_info['policy_type'] = 'default_allow_for_egress'

    #Parse Network policy ports and labels 
    if policy_info['policy_type'] == 'network_policy':
        ingress_egress_info = get_ingress_egress_policy_info(network_policy, uid)
        if 'podSelector' in network_policy[uid]['spec']:
             if 'matchLabels' in network_policy[uid]['spec']['podSelector']:    
                 policy_info['pod_selector_labels'] = network_policy[uid]['spec']['podSelector']['matchLabels']

    print ingress_egress_info

    policy_list = {}
    policy_list_ingress = {}
    policy_list_egress = {}

    print policy_info['policy_type']
    if policy_info['policy_type'] == 'network_policy':
        print "Network policy has both ingress and egress"
        policy_list_ingress = create_ingress_iptable_rules(ingress_egress_info['ingress'], policy_info)
        policy_list_egress = create_egress_iptable_rules(ingress_egress_info['egress'], policy_info)
    elif policy_info['policy_type'] == 'default_allow_for_ingress':
        print "Network policy is default allow for Ingress"
        policy_list = create_default_allow_iptable_rules(policy_info['policy_type'], policy_info['namespace'])
    elif policy_info['policy_type'] == 'default_allow_for_egress':
        print "network policy is default allow for egress"
        policy_list = create_default_allow_iptable_rules(policy_info['policy_type'], policy_info['namespace'])
    elif policy_info['policy_type'] == 'default_deny_for_ingress':
        policy_list = create_default_deny_iptable_rules(policy_info['policy_type'], policy_info['namespace'])
    elif policy_info['policy_type'] == 'default_deny_for_egress':
        policy_list = create_default_deny_iptable_rules(policy_info['policy_type'], policy_info['namespace'])
    elif policy_info['policy_type'] == 'default_deny_for_ingress_and_egress':
        policy_list = create_default_ingress_egress_deny_iptable_rules(policy_info['policy_type'], policy_info['namespace'])

    #print policy_list
    callback(policy_list)


def create_ingress_iptable_rules(ingress_info, policy_info):


    print ingress_info, policy_info
    policy_list = {}
    pod_arr = []
    if policy_info['policy_type'] == 'network_policy': 
        if 'pod_labels' in ingress_info:
            if 'namespace' in policy_info:
                if policy_info['namespace'] != ' ':
                    pod_arr = get_ingress_nodes_of_pods_pod_selector(policy_info['namespace'], ingress_info['pod_labels'])

    dest_pod_arr = []
    if policy_info['policy_type'] == 'network_policy':
        if 'pod_selector_labels' in policy_info:
            if 'namespace' in policy_info:
                if policy_info['namespace'] != ' ':
                    dest_pod_arr = get_ingress_nodes_of_pods_pod_selector(policy_info['namespace'], policy_info['pod_selector_labels'])
                

    namespace_pod_arr = []
    if 'namespace_labels' in ingress_info:
        namespace_pod_arr = get_ingress_nodes_of_pods_namespace_selector(ingress_info['namespace_labels'])
 
    print pod_arr, dest_pod_arr, namespace_pod_arr

    if pod_arr != []:
        if dest_pod_arr != []:
            for policy_pod in xrange(len(dest_pod_arr)):
                #Delete any existing rule
                #iptables -A FORWARD -m comment --comment "network policy chain for POD podname " -d <podIP> -j KUBE-NWPLCY-podnamehash

                policy_del = 'iptables -D FORWARD -d '+pod_arr[policy_pod]['pod_ip']+' -m comment --comment \" network policy chain for POD '+ dest_pod_arr[policy_pod]['pod_name'] + '\" -j KUBE-NWPLCY-'+ dest_pod_arr[policy_pod]['pod_name'][-5:]
                send_policy_to_node(dest_pod_arr[policy_pod]['node_name'], policy_del)
                time.sleep(1)
                print policy_del
                #Optionally add a per policy forwarding chain as follows
                #-A KUBE-NWPLCY-7UYHFX -m comment --comment "network policy rule for pod redis-slave-132015689-fksjt;policy: guestbook-network-policy" -j KUBE-NWPLCY-7UYHFX-SYJW74
                 
                #Add the new rule now
                policy = 'iptables -N' + ' KUBE-NWPLCY-'+ dest_pod_arr[policy_pod]['pod_name'][-5:]
                send_policy_to_node(dest_pod_arr[policy_pod]['node_name'], policy)
                time.sleep(1)

                policy = 'iptables -A FORWARD -d '+pod_arr[policy_pod]['pod_ip']+' -m comment --comment \" network policy chain for POD '+ dest_pod_arr[policy_pod]['pod_name'] + '\" -j KUBE-NWPLCY-'+ dest_pod_arr[policy_pod]['pod_name'][-5:]
                send_policy_to_node(dest_pod_arr[policy_pod]['node_name'], policy)
                time.sleep(1)

                policy = 'iptables -A FORWARD -d '+pod_arr[policy_pod]['pod_ip']+' -m comment --comment \" network policy chain for POD '+ dest_pod_arr[policy_pod]['pod_name'] + '\" -j KUBE-NWPLCY-'+ dest_pod_arr[policy_pod]['pod_name'][-5:]
                send_policy_to_node(dest_pod_arr[policy_pod]['node_name'], policy)
                time.sleep(1)

                if dest_pod_arr[policy_pod]['node_name'] in policy_list:
                    policy_list[dest_pod_arr[policy_pod]['node_name']].append(policy_del)
                else:
                    policy_list[dest_pod_arr[policy_pod]['node_name']] = []
                    policy_list[dest_pod_arr[policy_pod]['node_name']].append(policy_del)

                for pod in xrange(len(pod_arr)):
                    #-A KUBE-NWPLCY-7UYHFX -s 10.244.3.4/32 -p tcp -m tcp --dport 6379 -m comment --comment "nw policy rule for peer POD frontend-88237173-zir4y" -j ACCEPT   
                    #Delete any existing rule
                    #assuming only one pair of port and protocol for now
                    if 'ingress_ports' in ingress_info:
                        policy_del = 'iptables -D KUBE-NWPLCY-'+ dest_pod_arr[policy_pod]['pod_name'][-5:] + ' -s '+pod_arr[pod]['pod_ip']+' -p ' +str(ingress_info['ingress_ports'][0]['protocol'].lower())+ ' -m '+str(ingress_info['ingress_ports'][0]['protocol'].lower())+ ' --dport ' + str(ingress_info['ingress_ports'][0]['port'])+ ' -m comment --comment \"network policy for POD '+ dest_pod_arr[policy_pod]['pod_name'] + ' from pod' + pod_arr[pod]['pod_name'] + '\" -j ACCEPT'
                    
                    else:
                        policy_del = 'iptables -D KUBE-NWPLCY-'+ dest_pod_arr[policy_pod]['pod_name'][-5:] + ' -s '+pod_arr[pod]['pod_ip']+' -m comment --comment \"network policy for POD '+ dest_pod_arr[policy_pod]['pod_name'] + ' from pod' + pod_arr[pod]['pod_name'] + '\" -j ACCEPT'
                    send_policy_to_node(pod_arr[pod]['node_name'], policy_del)
                    time.sleep(1)
                    
                    #Add the new rule now
                    if 'ingress_ports' in ingress_info:
                        policy = 'iptables -A KUBE-NWPLCY-'+ dest_pod_arr[policy_pod]['pod_name'][-5:] + ' -s '+pod_arr[pod]['pod_ip']+' -p ' +str(ingress_info['ingress_ports'][0]['protocol'].lower())+ ' -m '+str(ingress_info['ingress_ports'][0]['protocol'].lower())+ ' --dport ' + str(ingress_info['ingress_ports'][0]['port'])+ ' -m comment --comment \"network policy for POD '+ dest_pod_arr[policy_pod]['pod_name'] + ' from pod' + pod_arr[pod]['pod_name'] + '\" -j ACCEPT'

                    else:
                        policy = 'iptables -A KUBE-NWPLCY-'+ dest_pod_arr[policy_pod]['pod_name'][-5:] + ' -s '+pod_arr[pod]['pod_ip']+' -m comment --comment \"network policy for POD '+ dest_pod_arr[policy_pod]['pod_name'] + ' from pod' + pod_arr[pod]['pod_name'] + '\" -j ACCEPT'

                    send_policy_to_node(dest_pod_arr[pod]['node_name'], policy)
                    time.sleep(1)
                    if dest_pod_arr[pod]['node_name'] in policy_list:
                        policy_list[dest_pod_arr[pod]['node_name']].append(policy_del)
                    else:
                        policy_list[dest_pod_arr[pod]['node_name']] = []
                        policy_list[dest_pod_arr[pod]['node_name']].append(policy_del)

    if pod_arr != []:
        if namespace_pod_arr != []:
            for policy_pod in xrange(len(dest_pod_arr)):
                #-A KUBE-NWPLCY-7UYHFX -s 10.244.3.4/32 -p tcp -m tcp --dport 6379 -m comment --comment "nw policy rule for peer POD frontend-88237173-zir4y" -j ACCEPT
                #Delete any existing rule
                #assuming only one pair of port and protocol for now
                if 'ingress_ports' in ingress_info:
                    policy_del = 'iptables -D KUBE-NWPLCY-'+ dest_pod_arr[policy_pod]['pod_name'][-5:] + ' -s '+namespace_pod_arr[pod]['pod_ip']+' -p ' +str(ingress_info['ingress_ports'][0]['protocol'].lower())+ ' -m '+str(ingress_info['ingress_ports'][0]['protocol'].lower())+ ' --dport ' + str(ingress_info['ingress_ports'][0]['port'])+ ' -m comment --comment \"network policy for POD '+ dest_pod_arr[policy_pod]['pod_name'] + ' from pod' + namespace_pod_arr[pod]['pod_name'] + '\" -j ACCEPT'

                else:
                    policy_del = 'iptables -D KUBE-NWPLCY-'+ dest_pod_arr[policy_pod]['pod_name'][-5:] + ' -s '+namespace_pod_arr[pod]['pod_ip']+' -m comment --comment \"network policy for POD '+ dest_pod_arr[policy_pod]['pod_name'] + ' from pod' + namespace_pod_arr[pod]['pod_name'] + '\" -j ACCEPT'
                    send_policy_to_node(dest_pod_arr[pod]['node_name'], policy_del)
                    time.sleep(1)

                #Add the new rule now
                if 'ingress_ports' in ingress_info:
                    policy = 'iptables -A KUBE-NWPLCY-'+ dest_pod_arr[policy_pod]['pod_name'][-5:] + ' -s '+namespace_pod_arr[pod]['pod_ip']+' -p ' +str(ingress_info['ingress_ports'][0]['protocol'].lower())+ ' -m '+str(ingress_info['ingress_ports'][0]['protocol'].lower())+ ' --dport ' + str(ingress_info['ingress_ports'][0]['port'])+ ' -m comment --comment \"network policy for POD '+ dest_pod_arr[policy_pod]['pod_name'] + ' from pod' + namespace_pod_arr[pod]['pod_name'] + '\" -j ACCEPT'

                else:
                    policy = 'iptables -A KUBE-NWPLCY-'+ dest_pod_arr[policy_pod]['pod_name'][-5:] + ' -s '+namespace_pod_arr[pod]['pod_ip']+' -m comment --comment \"network policy for POD '+ dest_pod_arr[policy_pod]['pod_name'] + ' from pod ' + namespace_pod_arr[pod]['pod_name'] + '\" -j ACCEPT'

                    send_policy_to_node(dest_pod_arr[pod]['node_name'], policy)
                    time.sleep(1)
                    if dest_pod_arr[pod]['node_name'] in policy_list:
                        policy_list[dest_pod_arr[pod]['node_name']].append(policy_del)
                    else:
                        policy_list[dest_pod_arr[pod]['node_name']] = []
                        policy_list[dest_pod_arr[pod]['node_name']].append(policy_del)

    if dest_pod_arr != []:
        if 'from_ip_block_cidr' in ingress_info:
            for pod in xrange(len(dest_pod_arr)):
                #-A KUBE-NWPLCY-7UYHFX -s 10.244.3.4/32 -p tcp -m tcp --dport 6379 -m comment --comment "nw policy rule for peer POD frontend-88237173-zir4y" -j ACCEPT
                #Delete any existing rule
                #assuming only one pair of port and protocol for now
                if 'ingress_ports' in ingress_info:
                    policy_del = 'iptables -D KUBE-NWPLCY-'+ dest_pod_arr[policy_pod]['pod_name'][-5:] + ' -s '+ingress_info['from_ip_block_cidr']+' -p ' +str(ingress_info['ingress_ports'][0]['protocol'].lower())+ ' -m '+str(ingress_info['ingress_ports'][0]['protocol'].lower())+ ' --dport ' + str(ingress_info['ingress_ports'][0]['port'])+ ' -m comment --comment \"network policy for POD '+ dest_pod_arr[policy_pod]['pod_name'] + ' from' + ingress_info['from_ip_block_cidr'] + '\" -j ACCEPT'
                    if 'except_ip_cidrs' in ingress_info:
                        policy_del_two = 'iptables -D KUBE-NWPLCY-'+ dest_pod_arr[policy_pod]['pod_name'][-5:] + ' -s '+ingress_info['except_ip_cidrs'][0]+' -p ' +str(ingress_info['ingress_ports'][0]['protocol'].lower())+ ' -m '+str(ingress_info['ingress_ports'][0]['protocol'].lower())+ ' --dport ' + str(ingress_info['ingress_ports'][0]['port'])+ ' -m comment --comment \"network policy for POD '+ dest_pod_arr[policy_pod]['pod_name'] + ' from' + ingress_info['except_ip_cidrs'][0] + '\" -j DROP'

                else:
                    policy_del = 'iptables -D KUBE-NWPLCY-'+ dest_pod_arr[policy_pod]['pod_name'][-5:] + ' -s '+namespace_pod_arr[pod]['pod_ip']+' -m comment --comment \"network policy for POD '+ dest_pod_arr[policy_pod]['pod_name'] + ' from pod' + namespace_pod_arr[pod]['pod_name'] + '\" -j ACCEPT'
                    if 'except_ip_cidrs' in ingress_info:
                        policy_del_two = 'iptables -D KUBE-NWPLCY-'+ dest_pod_arr[policy_pod]['pod_name'][-5:] + ' -s '+ingress_info['except_ip_cidrs'][0]+' -m comment --comment \"network policy for POD '+ dest_pod_arr[policy_pod]['pod_name'] + ' from' + ingress_info['except_ip_cidrs'][0] + '\" -j DROP'
                   
                send_policy_to_node(dest_pod_arr[pod]['node_name'], policy_del)
                time.sleep(1)
                send_policy_to_node(dest_pod_arr[pod]['node_name'], policy_del_two)
                time.sleep(1)


                if 'ingress_ports' in ingress_info:
                    policy = 'iptables -A KUBE-NWPLCY-'+ dest_pod_arr[policy_pod]['pod_name'][-5:] + ' -s '+ingress_info['from_ip_block_cidr']+' -p ' +str(ingress_info['ingress_ports'][0]['protocol'].lower())+ ' -m '+str(ingress_info['ingress_ports'][0]['protocol'].lower())+ ' --dport ' + str(ingress_info['ingress_ports'][0]['port'])+ ' -m comment --comment \"network policy for POD '+ dest_pod_arr[policy_pod]['pod_name'] + ' from' + ingress_info['from_ip_block_cidr'] + '\" -j ACCEPT'
                    if 'except_ip_cidrs' in ingress_info:
                        policy_two = 'iptables -A KUBE-NWPLCY-'+ dest_pod_arr[policy_pod]['pod_name'][-5:] + ' -s '+ingress_info['except_ip_cidrs'][0]+' -p ' +str(ingress_info['ingress_ports'][0]['protocol'].lower())+ ' -m '+str(ingress_info['ingress_ports'][0]['protocol'].lower())+ ' --dport ' + str(ingress_info['ingress_ports'][0]['port'])+ ' -m comment --comment \"network policy for POD '+ dest_pod_arr[policy_pod]['pod_name'] + ' from' + ingress_info['except_ip_cidrs'][0] + '\" -j DROP'

                else:
                    policy = 'iptables -A KUBE-NWPLCY-'+ dest_pod_arr[policy_pod]['pod_name'][-5:] + ' -s '+namespace_pod_arr[pod]['pod_ip']+' -m comment --comment \"network policy for POD '+ dest_pod_arr[policy_pod]['pod_name'] + ' from pod' + namespace_pod_arr[pod]['pod_name'] + '\" -j ACCEPT'
                    if 'except_ip_cidrs' in ingress_info:
                        policy_two = 'iptables -A KUBE-NWPLCY-'+ dest_pod_arr[policy_pod]['pod_name'][-5:] + ' -s '+ingress_info['except_ip_cidrs'][0]+ '-m comment --comment \"network policy for POD '+ dest_pod_arr[policy_pod]['pod_name'] + ' from' + ingress_info['except_ip_cidrs'][0] + '\" -j DROP'
              
                print policy  
                send_policy_to_node(dest_pod_arr[pod]['node_name'], policy)
                time.sleep(1)
                print policy_two
                send_policy_to_node(dest_pod_arr[pod]['node_name'], policy_two)
                time.sleep(1)

                if dest_pod_arr[pod]['node_name'] in policy_list:
                    policy_list[dest_pod_arr[pod]['node_name']].append(policy_del)
                    policy_list[dest_pod_arr[pod]['node_name']].append(policy_del_two)

                else:
                    policy_list[dest_pod_arr[pod]['node_name']] = []
                    policy_list[dest_pod_arr[pod]['node_name']].append(policy_del)
                    policy_list[dest_pod_arr[pod]['node_name']].append(policy_del_two)

    return policy_list                   


def create_egress_iptable_rules(egress_info, policy_info):
   
    policy_list = {} 
    #Implement for all possible scenarios like ingress - ipBlock, pod_selector_labels, namespace_labels etc.
    #For now, just using ports and ipBlock
    src_pod_arr = []
    if policy_info['policy_type'] == 'network_policy':
        if 'pod_selector_labels' in policy_info:
            if 'namespace' in policy_info:
                if policy_info['namespace'] != ' ':
                    src_pod_arr = get_ingress_nodes_of_pods_pod_selector(policy_info['namespace'], policy_info['pod_selector_labels'])
 

    if 'to_ip_block_cidr' in egress_info:
        if 'egress_ports' in egress_info:
            for policy_pod in xrange(len(src_pod_arr)):
                #Delete any existing rule
                #assuming only one pair of port and protocol for now
                if 'egress_ports' in egress_info:
                    policy_del = 'iptables -D KUBE-NWPLCY-'+ src_pod_arr[policy_pod]['pod_name'][-5:] + ' -d '+egress_info['to_ip_block_cidr']+' -p ' +str(egress_info['egress_ports'][0]['protocol'].lower())+ ' -m '+str(egress_info['egress_ports'][0]['protocol'].lower())+ ' --sport ' + str(egress_info['egress_ports'][0]['port']) + ' -m comment --comment \"network policy for POD '+ src_pod_arr[policy_pod]['pod_name'] + ' from' + egress_info['to_ip_block_cidr'] + '\" -j ACCEPT'

                else:
                    policy_del = 'iptables -D KUBE-NWPLCY-'+ src_pod_arr[policy_pod]['pod_name'][-5:] + ' -d '+egress_info['to_ip_block_cidr']+' -m comment --comment \"network policy for POD '+ src_pod_arr[policy_pod]['pod_name'] + ' from  ' + egress_info['to_ip_block_cidr'] + '\" -j ACCEPT'

                send_policy_to_node(src_pod_arr[policy_pod]['node_name'], policy_del)
                time.sleep(1)

                if 'egress_ports' in egress_info:
                    policy = 'iptables -A KUBE-NWPLCY-'+ src_pod_arr[policy_pod]['pod_name'][-5:] + ' -s '+egress_info['to_ip_block_cidr']+' -p ' + str(egress_info['egress_ports'][0]['protocol'].lower())+ ' -m '+str(egress_info['egress_ports'][0]['protocol'].lower())+ ' --sport ' + str(egress_info['egress_ports'][0]['port'])+ ' -m comment --comment \"network policy for POD '+ src_pod_arr[policy_pod]['pod_name'] + ' from' + egress_info['to_ip_block_cidr'] + '\" -j ACCEPT'

                else:
                    policy = 'iptables -A KUBE-NWPLCY-'+ src_pod_arr[policy_pod]['pod_name'][-5:] + ' -s '+egress_info['to_ip_block_cidr']+ ' -m comment --comment \"network policy for POD '+ src_pod_arr[policy_pod]['pod_name'] + ' from ' + egress_info['to_ip_block_cidr'] + '\" -j ACCEPT'
     
                send_policy_to_node(src_pod_arr[policy_pod]['node_name'], policy)
                time.sleep(1)

                if src_pod_arr[policy_pod]['node_name'] in policy_list:
                    policy_list[src_pod_arr[policy_pod]['node_name']].append(policy_del)
                else:
                    policy_list[src_pod_arr[policy_pod]['node_name']] = []
                    policy_list[src_pod_arr[policy_pod]['node_name']].append(policy_del)

    return policy_list
 
def create_default_ingress_egress_deny_iptable_rules(policy_type, namespace):
    if policy_type == 'default_deny_for_ingress_and_egress':
        policy_list_ingress = {}
        policy_list_ingress = def_create_default_deny_iptable_rules('default_deny_for_ingress', namespace)
        policy_list_egress = {}
        policy_list_egress = def_create_default_deny_iptable_rules('default_deny_for_egress', namespace)
        for key in policy_list_ingress:
            if key in policy_list_egress:
                for rules in policy_list_egress[key]:
                    policy_list_ingress[key].append(rules)
            else:
                policy_list_ingress[key] = []
                for rules in policy_list_egress[key]:
                    policy_list_ingress[key].append(rules)

        for key in policy_list_egress:
            if key not in policy_list_ingress:
                policy_list_ingress[key] = []
                for rules in policy_list_egress[key]:
                    policy_list_ingress[key].append(rules)
         
        return policy_list_ingress

def create_default_deny_iptable_rules(policy_type, namespace):
   
    pod_arr = []
    policy_list = {}
    if policy_type == 'default_deny_for_ingress':
        if namespace != ' ':
            pod_arr = get_pods_of_namespace(namespace)
            for pod in xrange(len(pod_arr)):
                #Delete any existing rule
                policy_del = 'iptables -D OUTPUT -d '+pod_arr[pod]['pod_ip']+' -m comment --comment \"default ingress deny network policy for POD '+ pod_arr[pod]['pod_name'] + '\" -j DROP'
                send_policy_to_node(pod_arr[pod]['node_name'], policy_del)
                time.sleep(1)
                #Add the new rule now
                policy = 'iptables -I OUTPUT -d '+pod_arr[pod]['pod_ip']+' -m comment --comment \"default ingress deny network policy for POD '+ pod_arr[pod]['pod_name'] + '\" -j DROP'
                send_policy_to_node(pod_arr[pod]['node_name'], policy)
                time.sleep(1)
                if pod_arr[pod]['node_name'] in policy_list:
                    policy_list[pod_arr[pod]['node_name']].append(policy_del)
                else:
                    policy_list[pod_arr[pod]['node_name']] = []
                    policy_list[pod_arr[pod]['node_name']].append(policy_del)

    elif policy_type == 'default_deny_for_egress':
        if namespace != ' ':
            pod_arr = get_pods_of_namespace(namespace)
            for pod in xrange(len(pod_arr)):
                #delete any exisiting rule
                policy_del = 'iptables -D INPUT -s '+pod_arr[pod]['pod_ip']+' -m comment --comment \"default egress deny network policy for POD '+ pod_arr[pod]['pod_name'] + '\" -j DROP'
                send_policy_to_node(pod_arr[pod]['node_name'], policy_del)
                time.sleep(1)
                #Add the new rule
                policy = 'iptables -I INPUT -s '+pod_arr[pod]['pod_ip']+' -m comment --comment \"default egress deny network policy for POD '+ pod_arr[pod]['pod_name'] + '\" -j DROP'
                send_policy_to_node(pod_arr[pod]['node_name'], policy)
                time.sleep(1)
                if pod_arr[pod]['node_name'] in policy_list:
                    policy_list[pod_arr[pod]['node_name']].append(policy_del)
                else:
                    policy_list[pod_arr[pod]['node_name']] = []
                    policy_list[pod_arr[pod]['node_name']].append(policy_del)

    return policy_list

def create_default_allow_iptable_rules(policy_type, namespace):
    
    pod_arr = []
    policy_list = {}
    if policy_type == 'default_allow_for_ingress':
        if namespace != ' ':
            pod_arr = get_pods_of_namespace(namespace)
            for pod in xrange(len(pod_arr)):
                #Delete any existing rule 
                policy_del = 'iptables -D OUTPUT -d '+pod_arr[pod]['pod_ip']+' -m comment --comment \"default ingress allow network policy for POD '+ pod_arr[pod]['pod_name'] + '\" -j ACCEPT'
                send_policy_to_node(pod_arr[pod]['node_name'], policy_del)
                time.sleep(1)
                #Add the new rule now
                policy = 'iptables -I OUTPUT -d '+pod_arr[pod]['pod_ip']+' -m comment --comment \"default ingress allow network policy for POD '+ pod_arr[pod]['pod_name'] + '\" -j ACCEPT'
                send_policy_to_node(pod_arr[pod]['node_name'], policy)
                time.sleep(1)
                if pod_arr[pod]['node_name'] in policy_list:
                    policy_list[pod_arr[pod]['node_name']].append(policy_del)
                else:
                    policy_list[pod_arr[pod]['node_name']] = []
                    policy_list[pod_arr[pod]['node_name']].append(policy_del)

    elif policy_type == 'default_allow_for_egress':
        if namespace != ' ':
            pod_arr = get_pods_of_namespace(namespace)
            for pod in xrange(len(pod_arr)):
                #delete any exisiting rule
                policy_del = 'iptables -D INPUT -s '+pod_arr[pod]['pod_ip']+' -m comment --comment \"default egress allow network policy for POD '+ pod_arr[pod]['pod_name'] + '\" -j ACCEPT'        
                send_policy_to_node(pod_arr[pod]['node_name'], policy_del)
                time.sleep(1)
                #Add the new rule
                policy = 'iptables -I INPUT -s '+pod_arr[pod]['pod_ip']+' -m comment --comment \"default egress allow network policy for POD '+ pod_arr[pod]['pod_name'] + '\" -j ACCEPT'
                send_policy_to_node(pod_arr[pod]['node_name'], policy)
                time.sleep(1)
                if pod_arr[pod]['node_name'] in policy_list:
                    policy_list[pod_arr[pod]['node_name']].append(policy_del)
                else:
                    policy_list[pod_arr[pod]['node_name']] = []
                    policy_list[pod_arr[pod]['node_name']].append(policy_del)

    return policy_list              

def get_ingress_egress_policy_info(network_policy, uid):
    ingress_info = {}
    egress_info = {}
    ingress_egress_info = {}
    for policyTypes in network_policy[uid]['spec']['policyTypes']:
        if policyTypes == 'Ingress':
            for items in network_policy[uid]['spec']['ingress']:
                if 'ports' in items:
                    ingress_info['ingress_ports'] = items['ports']
                for filters in items['from']:
                    if 'ipBlock' in filters:
                        ingress_info['from_ip_block_cidr'] = filters['ipBlock']['cidr']
                        if 'except' in filters['ipBlock']:
                            ingress_info['except_ip_cidrs'] = filters['ipBlock']['except']
                    elif 'namespaceSelector' in filters:
                        if 'matchLabels' in filters['namespaceSelector']:
                            ingress_info['namespace_labels'] = filters['namespaceSelector']['matchLabels']
                    elif 'podSelector' in filters:
                        if 'matchLabels' in filters['podSelector']:
                            ingress_info['pod_labels'] = filters['podSelector']['matchLabels']
        elif policyTypes == 'Egress':
            for items in network_policy[uid]['spec']['egress']:
                if 'ports' in items:
                    egress_info['egress_ports'] = items['ports']
                for filters in items['to']:
                    if 'ipBlock' in filters:
                        egress_info['to_ip_block_cidr'] = filters['ipBlock']['cidr']
                        if 'except' in filters['ipBlock']:
                            egress_info['except_ip_cidrs'] = filters['ipBlock']['except']
                    elif 'namespaceSelector' in filters:
                        if 'matchLabels' in filters['namespaceSelector']:
                            egress_info['namespace_labels'] = filters['namespaceSelector']['matchLabels']
                    elif 'podSelector' in filters:
                        egress_info['pod_labels'] = filters['podSelector']['matchLabels']

    ingress_egress_info['ingress'] = ingress_info
    ingress_egress_info['egress'] = egress_info
    return ingress_egress_info 

def get_pods_of_namespace(namespace):
    
    pod_arr = []
    pod_dict = {}
    configuration = config.load_kube_config()
    api_instance_pod = kubernetes.client.CoreV1Api(kubernetes.client.ApiClient(configuration))
    include_uninitialized = True
    limit = 56
    pretty = 'true'
    timeout_seconds = 30
    watch = False

    api_response = api_instance_pod.list_namespaced_pod(namespace, pretty=pretty, include_uninitialized=include_uninitialized, limit=limit, timeout_seconds=timeout_seconds)

    for pod in xrange(len(api_response.items)):
        pod_dict['pod_name'] = api_response.items[pod].metadata.name
        pod_dict['node_name'] = api_response.items[pod].spec.node_name
        pod_dict['pod_ip'] = api_response.items[pod].status.pod_ip
        pod_arr.append(pod_dict)
        pod_dict = {}

    return pod_arr


def get_ingress_nodes_of_pods_pod_selector(namespace, pod_labels):
  
    pod_dict = {}
    pod_arr = []  
    configuration = config.load_kube_config()
    api_instance_pod = kubernetes.client.CoreV1Api(kubernetes.client.ApiClient(configuration))
    include_uninitialized = True
    for key in pod_labels:
        pod_labels_str = key+'='+pod_labels[key]
    label_selector = pod_labels_str
    limit = 56
    pretty = 'true'
    timeout_seconds = 30
    watch = False

    api_response = api_instance_pod.list_namespaced_pod(namespace, pretty=pretty, include_uninitialized=include_uninitialized, label_selector=label_selector, limit=limit, timeout_seconds=timeout_seconds)
    
    for pod in xrange(len(api_response.items)):
        pod_dict['pod_name'] = api_response.items[pod].metadata.name
        pod_dict['node_name'] = api_response.items[pod].spec.node_name
        pod_dict['pod_ip'] = api_response.items[pod].status.pod_ip
        pod_arr.append(pod_dict)
        pod_dict = {}

    return pod_arr
    
def get_ingress_nodes_of_pods_namespace_selector(namespace_selector_labels):

    pod_arr = []
    pod_dict = {}
    configuration = config.load_kube_config()
    api_instance_pod = kubernetes.client.CoreV1Api(kubernetes.client.ApiClient(configuration))
    include_uninitialized = True
    for key in namespace_selector_labels:
        namespace_labels = key+'='+namespace_selector_labels[key]
    label_selector = namespace_labels
    limit = 56
    pretty = 'true'
    timeout_seconds = 30
    watch = False

    api_response = api_instance_pod.list_pod_for_all_namespaces(pretty=pretty, include_uninitialized=include_uninitialized, label_selector=label_selector, limit=limit, timeout_seconds=timeout_seconds)
    
    for pod in xrange(len(api_response.items)):
        pod_dict['pod_name'] = api_response.items[pod].metadata.name
        pod_dict['node_name'] = api_response.items[pod].spec.node_name
        pod_dict['pod_ip'] = api_response.items[pod].status.pod_ip
        pod_arr.append(pod_dict)
        pod_dict = {}

    return pod_arr

def create_updated_policy_rules(network_policy_updated, callback):
    print 'Checking updated policy contents to add iptables based rules'
    time.sleep(1)
    callback(network_policy_updated)

@gen.engine
def watch_for_policies():
    config.load_kube_config()
    v1 = client.ExtensionsV1beta1Api()
    network_policy = {}
    network_policy_update = {} 
    w = watch.Watch()
    for event in w.stream(v1.list_network_policy_for_all_namespaces):
        print event
        print("Event: %s %s %s" % (event['type'], event['object'].kind, event['object'].metadata.name))
        if event['type'] == 'ADDED':
           if event['object'].metadata.uid not in network_policy:
              network_policy[event['object'].metadata.uid] = event['raw_object']
              result = yield gen.Task(create_new_policy_rules, network_policy, event['object'].metadata.uid)
        elif event['type'] == 'UPDATED':
           network_policy_updated[event['object'].metadata.uid] = event['raw_object']
           result = yield gen.Task(create_updated_policy_rules, network_policy_updated)
        IOLoop.instance().stop() 


if __name__ == "__main__":
    watch_for_policies()
    IOLoop.instance().start()
