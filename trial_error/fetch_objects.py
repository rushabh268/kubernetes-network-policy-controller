from __future__ import print_function
import time
import kubernetes.client
import kubernetes.config as config
from kubernetes.client.rest import ApiException
from pprint import pprint

# Configure API key authorization: BearerToken
#configuration = kubernetes.client.Configuration()
#configuration.api_key['authorization'] = 'YOUR_API_KEY'
# Uncomment below to setup prefix (e.g. Bearer) for API key, if needed
# configuration.api_key_prefix['authorization'] = 'Bearer'

def main():
    configuration = config.load_kube_config()

    # create an instance of the API class
    api_instance = kubernetes.client.ExtensionsV1beta1Api(kubernetes.client.ApiClient(configuration))
    api_instance_pod = kubernetes.client.CoreV1Api(kubernetes.client.ApiClient(configuration))
    #_continue = '_continue_example'
    #field_selector = 'field_selector_example'
    include_uninitialized = True
    label_selector = 'tier=frontend'
    limit = 56
    pretty = 'true'
    #resource_version = 'resource_version_example'
    timeout_seconds = 56
    watch = False
    namespace = 'default'

#Fetch the network policies across all namespaces
    try: 
        #api_response = api_instance.list_network_policy_for_all_namespaces(_continue=_continue, field_selector=field_selector, include_uninitialized=include_uninitialized, label_selector=label_selector, limit=limit, pretty=pretty, resource_version=resource_version, timeout_seconds=timeout_seconds, watch=watch)
        api_response = api_instance.list_network_policy_for_all_namespaces(include_uninitialized=include_uninitialized, limit=limit, pretty=pretty, timeout_seconds=timeout_seconds, watch=watch)
        pprint(api_response)
        if len(api_response.items) == 0:
           print("No new network policies have been created or updated")
        else:
           for policy in api_response.items:
               
    except ApiException as e:
        print("Exception when calling ExtensionsV1beta1Api->list_network_policy_for_all_namespaces: %s\n" % e)

#Fetch pods in a particular namespace
    try: 
        #api_response = api_instance.list_namespaced_pod(namespace, pretty=pretty, _continue=_continue, field_selector=field_selector, include_uninitialized=include_uninitialized, label_selector=label_selector, limit=limit, resource_version=resource_version, timeout_seconds=timeout_seconds, watch=watch)
        api_response = api_instance_pod.list_namespaced_pod(namespace, pretty=pretty, include_uninitialized=include_uninitialized, limit=limit, timeout_seconds=timeout_seconds)
        pprint(api_response)
    except ApiException as e:
        print("Exception when calling CoreV1Api->list_namespaced_pod: %s\n" % e)

#Fetch pods in a particular namespace with a particular label
    try:
        #api_response = api_instance.list_namespaced_pod(namespace, pretty=pretty, _continue=_continue, field_selector=field_selector, include_uninitialized=include_uninitialized, label_selector=label_selector, limit=limit, resource_version=resource_version, timeout_seconds=timeout_seconds, watch=watch)
        api_response = api_instance_pod.list_namespaced_pod(namespace, pretty=pretty, include_uninitialized=include_uninitialized, label_selector=label_selector, limit=limit, timeout_seconds=timeout_seconds)
        pprint(api_response)
    except ApiException as e:
        print("Exception when calling CoreV1Api->list_namespaced_pod: %s\n" % e)


if __name__ == '__main__':
    main()
