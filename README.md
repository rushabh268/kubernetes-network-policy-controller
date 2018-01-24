# kubernetes-network-policy-controller

Kubernetes python client based Network Policy controller for Kubernetes

The design relies on python Kubernetes client which gives an easy python API to talk to the API server. What the network_policy_controller does is as follows:

1. It uses async module of the Tornado package. The async module of Tornado package is used to create a watcher for network policy object creation. 
2. Whenever a network policy object is created, it triggers a parsing module which will parse the network policy event. 
3. After the network policy object is parsed, it is categorized into whether its an ingress policy or an egress policy or both or whether it is one of the default allow or deny policy
4. Once the policy type is determined, the pods on which the policy is to be applied are determined and stored in a list
5. Also, the pods from which ingress/egress connections are allowed are determined and stored in another list
6. Once the source and destination pods are determined, the iptables rules are formed for each of the pods using the following logic:

```
//For each destination pod selected by the pod selector that is running on this host, add
//IPTables rules of the form
//iptables -N KUBE-NWPLCY-podnamehash
//iptables -A FORWARD -m comment --comment "network policy chain for POD podname " -d <podIP> -j KUBE-NWPLCY-podnamehash
//for each peer pod allowed by an ingress rule in this policy
//iptables -I KUBE-NWPLCY-podnamehash -s <peer_pod_IP> --dport <dst port> -j ACCEPT
//iptables -A KUBE-NWPLCY-podnamehash -j REJECT
//E.g.,
//iptables -N KUBE-NWPLCY-7UYHFX
//-A FORWARD -d 10.244.5.4/32 -m comment --comment "nw policy chain for POD redis-slave-132015689-fksjt" -j KUBE-NWPLCY-7UYHFX
//-A KUBE-NWPLCY-7UYHFX -s 10.244.3.4/32 -p tcp -m tcp --dport 6379 -m comment --comment "nw policy rule for peer POD frontend-88237173-zir4y" -j ACCEPT
//-A KUBE-NWPLCY-7UYHFX -s 10.244.3.3/32 -p tcp -m tcp --dport 6379 -m comment --comment "nw policy rule for peer POD frontend-88237173-by8e6 -j ACCEPT
//-A KUBE-NWPLCY-7UYHFX -s 10.244.3.8/32 -p tcp -m tcp --dport 6379 -m comment --comment "nw policy rule for peer POD frontend-88237173-p7up8" -j ACCEPT
//-A KUBE-NWPLCY-7UYHFX -j REJECT
```

7. The assumption is that by default the traffic is dropped/denied in the same namespace
8. Once the iptable rules are determined, they are sent to the node using pika module of rabbitmq. The rabbitmq server need to run on the master node where our network_policy_controller.py will also run and it will communicate with a node_agent.py on every node which has the master config to communicate with the rabbitmq server
9. Also, before the actual rules are applied, the controller tries to delete if there are any existing rules for this pod
10. Once the rules are received by the node for a pod, they are just added to the iptables

Setup:

Kubernetes 1.9.1 with one master & node 

