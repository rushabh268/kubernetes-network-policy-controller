#!/usr/bin/env python
import pika
import sys
import os

def callback(ch, method, properties, body):
    print(" [x] %r:%r" % (method.routing_key, body))
    print("Adding policy: "+body)
    cmd = body+' > tmp'
    os.system(cmd)
    print open('tmp', 'r').read()
    os.remove('tmp') 

def receive_iptables_policy(node_name):

    connection = pika.BlockingConnection(pika.ConnectionParameters(host='20.100.100.101'))
    channel = connection.channel()

    channel.exchange_declare(exchange='topic_logs', exchange_type='topic')
    result = channel.queue_declare(exclusive=True)
    queue_name = result.method.queue
    binding_keys = node_name

    if not binding_keys:
       sys.stderr.write("Usage: %s [binding_key]...\n" % node_name)
       sys.exit(1)

    for binding_key in binding_keys:
        channel.queue_bind(exchange='topic_logs', queue=queue_name, routing_key=binding_key)

    print(' [*] Waiting for the iptable command.')

    channel.basic_consume(callback, queue=queue_name, no_ack=True)
    channel.start_consuming()

def main():
    
    #determine node_name
    node_name = "ovs-9.#"
    receive_iptables_policy(node_name)    

if __name__ == '__main__':
    main()



