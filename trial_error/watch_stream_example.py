import asyncio
import logging

from kubernetes import client, config, watch

#def main():

logger = logging.getLogger('k8s_events')
logger.setLevel(logging.DEBUG)

config.load_kube_config()

v1 = client.CoreV1Api()
v1ext = client.ExtensionsV1beta1Api()

async def pods():
    w = watch.Watch()
    for event in w.stream(v1.list_pod_for_all_namespaces):
        logger.info("Event: %s %s %s" % (event['type'], event['object'].kind, event['object'].metadata.name))
        await asyncio.sleep(0) 
    
async def deployments():
    w = watch.Watch()
    for event in w.stream(v1ext.list_deployment_for_all_namespaces):
        logger.info("Event: %s %s %s" % (event['type'], event['object'].kind, event['object'].metadata.name))
        await asyncio.sleep(0)

ioloop = asyncio.get_event_loop()

ioloop.create_task(pods())
ioloop.create_task(deployments())
ioloop.run_forever()
