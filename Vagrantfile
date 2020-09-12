dir = File.expand_path("..", __FILE__)

Vagrant.configure("2") do |config|
  config.vagrant.plugins = "vagrant-reload"

  config.vm.define "adfs", autostart: false do |adfs|
    adfs.vm.hostname = "adfs"
    adfs.vm.box = "StefanScherer/windows_2019"

    adfs.vm.provider "virtualbox" do |v|
      v.memory = 2048
      v.gui = true
      v.customize ["modifyvm", :id, "--clipboard", "bidirectional"]
    end

    # If you change this IP, also change the DNS server for the "web" VM.
    adfs.vm.network "private_network", ip: "10.10.10.2"

    # Some winrm hacking
    # It prevents the connection with the VM from dropping
    # after promoting it to a domain controller
    adfs.winrm.timeout = 180
    adfs.winrm.retry_limit = 20
    adfs.winrm.retry_delay = 10
    adfs.winrm.transport = :plaintext
    adfs.winrm.basic_auth_only = true

    # Setup the domain controller
    adfs.vm.provision "shell", privileged: false, path: File.join(dir, 'vagrant', '01-setup-domain.ps1')
    adfs.vm.provision :reload
    adfs.vm.provision "shell", privileged: false, path: File.join(dir, 'vagrant', '02-setup-vagrant-user.ps1')
    # Setup ADFS
    adfs.vm.provision "shell", privileged: false, path: File.join(dir, 'vagrant', '03-setup-adfs.ps1')
    adfs.vm.provision :reload
    # Configure ADFS for use with the example project
    adfs.vm.provision "shell", privileged: false, path: File.join(dir, 'vagrant', '04-example-adfs-config.ps1')
  end

  config.vm.define "web" do |web|
    web.vm.hostname = "web"
    web.vm.box = "debian/buster64"

    # If you change this IP, you also have to change it in the file 03-example-adfs-config.ps1
    web.vm.network "private_network", ip: "10.10.10.10"
    web.vm.network "forwarded_port", guest: 8000, host: 8000

    # Install all needed tools and migrate the 2 example django projects
    web.vm.provision "shell", privileged: true, inline: <<-SHELL
      set -x
      apt-get update
      apt-get install -y python3-pip
      # Install django-auth-adfs in editable mode
      pip3 install -e /vagrant
      # Install DRF to demo the API integration
      pip3 install djangorestframework django-filter
      # run migrate command for both example projects
      python3 /vagrant/demo/adfs/manage.py makemigrations polls
      python3 /vagrant/demo/adfs/manage.py migrate
      python3 /vagrant/demo/formsbased/manage.py makemigrations polls
      python3 /vagrant/demo/formsbased/manage.py migrate
      # Set fixed hosts entry to ADFS server
      echo "10.10.10.2 adfs.example.com" >> /etc/hosts
    SHELL
  end
end
