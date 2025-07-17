# Kubeadm system checks

This is a task for running kubeadm system preflight checks.  Consult kubeadm upstream for documentation
on the individual preflight checks (https://kubernetes.io/docs/reference/setup-tools/kubeadm/implementation-details/).

To update the kubeadm release binary, you can acquire and replace it from the k8s.io release endpoints, i.e. 

# Updating kubeadm version

In this repo we freeze the kubeadm version, since the
system checks dont change much, thus making the need to get it
dynamically obviated.

If you need to update kubeadm for some reason, just run... (modify the v.15.0 version to whatever your desired release is).

```
wget https://dl.k8s.io/v1.15.0/kubernetes-server-linux-amd64.tar.gz
tar -xvf kubernetes-server-linux-amd64.tar.gz
cp kubernetes/server/bin/kubeadm kubeadm
git add kubeadm
git commit -m "Updated kubeadm to version 1.15"
```

