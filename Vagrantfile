Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/xenial64"

  def create(config, hostname, ip)
    config.vm.define hostname do |host|
      host.vm.hostname = hostname
      host.vm.network "private_network", ip: ip
      host.vm.provision "shell", inline: "echo ubuntu:ubuntu | chpasswd"
      host.vm.provision "shell", inline: "apt-get update && apt-get install -y python-minimal"
      config.vm.provision "ansible" do |ansible|
        ansible.verbose = "v"
        ansible.playbook = "pf9-express.yml"
        ansible.groups = {
            "k8s-master" => ["vm1"],
            "k8s-worker"  => ["vm2"],
            "hypervisors" => []
        }
        ansible.extra_vars = {
          selinuxoff: true,
          autoreg: false,
        }
      end
    end
  end
  create(config, "vm1", "192.168.99.101")
  create(config, "vm2", "192.168.99.102")
end
