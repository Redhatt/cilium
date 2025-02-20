#! /bin/bash

REPO_ROOT=$PWD
KUBEPROXY_MODE="none" \
WORKERS=2 \
CONTROLPLANES=1 \
CLUSTER_NAME=kind \
make kind && \
make kind-image && \
kind export kubeconfig --name kind

helm upgrade -i cilium ./install/kubernetes/cilium \
  --wait \
  --namespace kube-system \
  --set k8sServiceHost="kind-control-plane" \
  --set k8sServicePort="6443" \
  --set debug.enabled=true \
  --set debug.verbose=datapath \
  --set pprof.enabled=true \
  --set enableIPv4Masquerade=false \
  --set enableIPv6Masquerade=false \
  --set enableIPv4Masquerade=false \
  --set hostFirewall.enabled=false \
  --set socketLB.hostNamespaceOnly=true \
  --set kubeProxyReplacement=true \
  --set nodeinit.enabled=true \
  --set ipam.mode=kubernetes \
  --set ipv4.enabled=true \
  --set ipv4NativeRoutingCIDR=10.244.0.0/16 \
  --set ipv6.enabled=false \
  --set image.override="localhost:5000/cilium/cilium-dev:local" \
  --set image.pullPolicy=Never \
  --set operator.image.override="localhost:5000/cilium/operator-generic:local" \
  --set operator.image.pullPolicy=Never \
  --set operator.image.suffix="" \
  --set securityContext.privileged=true \
  --set gatewayAPI.enabled=false \
  --set socketLB.enabled=false \
  --set bpf.hostLegacyRouting=true \
  --set endpointRoutes.enabled=true \
  --set localRedirectPolicy=true \
  --set ipTracing.optionType=136

# cilium config set ip-option-tracing-type 136
cilium hubble enable

k rollout status ds -n kube-system cilium && k rollout status ds -n kube-system cilium


k apply -f - <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: client
  labels:
    app: client
spec:
  replicas: 1
  selector:
    matchLabels:
      app: client
  template:
    metadata:
      labels:
        app: client
    spec:
      affinity:
        podAntiAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
          - labelSelector:
              matchLabels:
                app: server
            topologyKey: kubernetes.io/hostname
      containers:
      - name: client
        image: nicolaka/netshoot
        command:
        - sleep
        args:
        - "999999"
EOF

k apply -f - <<EOF
apiVersion: v1
kind: Service
metadata:
  name: server
spec:
  selector:
    app: server
  ports:
  - port: 80
    name: http
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: server
  labels:
    app: server
spec:
  replicas: 1
  selector:
    matchLabels:
      app: server
  template:
    metadata:
      labels:
        app: server
    spec:
      affinity:
        podAntiAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
          - labelSelector:
              matchLabels:
                app: client
            topologyKey: kubernetes.io/hostname
      containers:
      - name: server
        image: nginx
        ports:
        - containerPort: 80
EOF

k exec -it deployment/client -- nping --tcp -p 80 $( kubectl get svc server -ojsonpath='{.spec.clusterIP}' )  --df -c 1 --ip-options='\x88\x04\x12\x34'

k exec 
gcloud container clusters get-credentials server --location us-central1-c
cilium hubble port-forward&
./hubble observe -f --ip-trace-id 1234
