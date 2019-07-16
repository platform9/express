Vagrant.configure("2") do |config|
  config.vm.box = "centos/7"

  def create(config, hostname, ip)
    config.vm.define hostname do |host|
      host.vm.hostname = hostname
      host.vm.network "private_network", ip: ip
      config.vm.provision "ansible" do |ansible|
        ansible.verbose = "v"
        ansible.playbook = "pf9-express-contrib.yml"

      	# Example of how to test selinux...
        # ansible.groups = {
        #    "apply_selinux_policies" => ["machine1", "machine2"],
        #    "hypervisors" => []
        # }
        ansible.groups = {
		      "k8s_master" => ["machine1"],
		      "k8s_worker" => ["machine2"],
		      "hypervisors" => []
      	}
        ansible.extra_vars = {
          autoreg: "false",
          du_url: "127.0.0.1",
          du_fqdn: "localhost"
        }
      end
    end
  end
  create(config, "machine1", "192.168.99.101")
  create(config, "machine2", "192.168.99.102")
end