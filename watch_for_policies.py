from kubernetes import client, config, watch
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
    message = ' '.join(iptables) or 'No action!'
    channel.basic_publish(exchange='topic_logs', routing_key=routing_key, body=message)
    print(" [x] Sent %r:%r" % (routing_key, message))
    connection.close()

def create_new_policy_rules(network_policy, callback):
    print 'Checking policy contents to add iptables based rules'
    print network_policy
    #node_name and iptables to be determined by parsing network_policy and searching for pods
    node_name = 'ovs-10.mvdcdev44.us.alcatel-lucent.com'
    iptables = 'Hello world!'
    send_policy_to_node(node_name, iptables)
    time.sleep(1)
    callback(network_policy)

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
              result = yield gen.Task(create_new_policy_rules, network_policy)
        elif event['type'] == 'UPDATED':
           network_policy_updated[event['object'].metadata.uid] = event['raw_object']
           result = yield gen.Task(create_updated_policy_rules, network_policy_updated)
        print 'result is', result
        IOLoop.instance().stop() 


if __name__ == "__main__":
    watch_for_policies()
    IOLoop.instance().start()
