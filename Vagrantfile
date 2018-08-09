# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure(2) do |config|
  config.vm.box = "ubuntu/bionic64"
  config.vm.host_name = "fexm"

  # 3 Ports for 3 Dashboards
  for i in 5307..5309
    config.vm.network :forwarded_port, guest: i, host: i
  end

  # An additional range of ports for AFL-TW
  for i in 53007..53107
    config.vm.network :forwarded_port, guest: i, host: i
  end

  config.vm.provision "shell" do |s|
    s.path = "./fexm/scripts/provision.sh"
    s.privileged = false
  end

  config.vm.provider "virtualbox" do |v|
    v.name = "fexm-vm"
    v.memory = 8192
    v.cpus = 8
    v.customize ['modifyvm', :id, '--cableconnected1', 'on']
    v.customize ["modifyvm", :id, "--natdnsproxy1", "on"]
    v.customize ["modifyvm", :id, "--natdnshostresolver1", "on"]
  end

  # A private dhcp network is required for NFS to work (on Windows hosts, at least)
  config.vm.network "private_network", type: "dhcp"

  # We want vagrant and interactive docker to look the same.
  config.vm.synced_folder ".", "/vagrant", disabled: true

## In case you don't want to use nfs, use these lines instead (but it's slower)
# config.vm.synced_folder "./fexm", "/fexm", create: true
#  config.vm.synced_folder "./seeds", "/seeds", create: true
#  config.vm.synced_folder "./data", "/data", create: true

  config.vm.synced_folder "./fexm", "/fexm", create: true, type: "nfs"
  config.vm.synced_folder "./seeds", "/seeds", create: true, type: "nfs"
# config.vm.synced_folder "./data", "/data", create: true, type: "nfs"

  # config.ssh.forward_agent = true
  config.ssh.forward_x11 = true

  if Vagrant.has_plugin?("vagrant-disksize")
    config.disksize.size = '200GB'
  end

  if Vagrant.has_plugin?("vagrant-cachier")
    # More info on http://fgrehm.viewdocs.io/vagrant-cachier/usage
    config.cache.scope = :box
    config.cache.synced_folder_opts = { type: :nfs, mount_options: ['rw', 'vers=3', 'tcp', 'nolock'] }
  end

end
