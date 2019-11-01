Vagrant.configure("2") do |config|
  config.vm.define "adfs2016", autostart: false do |adfs2016|

    adfs2016.vm.box = "cdaf/WindowsServer"

    adfs2016.vm.provider "virtualbox" do |v|
      v.memory = 2048
      v.gui = true
      v.customize ["modifyvm", :id, "--clipboard", "bidirectional"]
    end

    # If you change this IP, also change the DNS server for the "web" VM.
    adfs2016.vm.network "private_network", ip: "10.0.0.2"

    # Some winrm hacking
    # It prevents the connection with the VM from dropping
    # after promoting it to a domain controller
    adfs2016.winrm.timeout = 180
    adfs2016.winrm.retry_limit = 20
    adfs2016.winrm.retry_delay = 10
    adfs2016.winrm.transport = :plaintext
    adfs2016.winrm.basic_auth_only = true
    adfs2016.winrm.username = "administrator"
    adfs2016.winrm.password = "vagrant"

    # Setup the domain controller
    adfs2016.vm.provision "shell", privileged: true, path: "vagrant\\01-setup-domain.ps1"
    adfs2016.vm.provision :reload
    # Setup ADFS
    adfs2016.vm.provision "shell", privileged: true, path: "vagrant\\02-setup-adfs.ps1"
    adfs2016.vm.provision :reload
    # Configure ADFS for use with the example project
    adfs2016.vm.provision "shell", privileged: true, path: "vagrant\\03-example-adfs-config.ps1"
  end

  config.vm.define "adfs2012", autostart: false do |adfs2012|

    adfs2012.vm.box = "fujiiface/2012r2"

    adfs2012.vm.provider "virtualbox" do |v|
      v.memory = 2048
      v.gui = true
      v.customize ["modifyvm", :id, "--clipboard", "bidirectional"]
    end

    # If you change this IP, also change the DNS server for the "web" VM.
    adfs2012.vm.network "private_network", ip: "10.0.0.2"

    # Some winrm hacking
    # It prevents the connection with the VM from dropping
    # after promoting it to a domain controller
    adfs2012.winrm.timeout = 180
    adfs2012.winrm.retry_limit = 20
    adfs2012.winrm.retry_delay = 10
    adfs2012.winrm.transport = :plaintext
    adfs2012.winrm.basic_auth_only = true
    adfs2012.winrm.username = "administrator"
    adfs2012.winrm.password = "vagrant"

    # Setup the domain controller
    adfs2012.vm.provision "shell", privileged: true, path: "vagrant\\01-setup-domain.ps1"
    adfs2012.vm.provision :reload
    # Setup ADFS
    adfs2012.vm.provision "shell", privileged: true, path: "vagrant\\02-setup-adfs.ps1"
    adfs2012.vm.provision :reload
    # Configure ADFS for use with the example project
    adfs2012.vm.provision "shell", privileged: true, path: "vagrant\\03-example-adfs-config.ps1"
  end

  config.vm.define "web" do |web|
    web.vm.hostname = "web"
    web.vm.box = "bento/debian-10"

    # If you change this IP, you also have to change it in the file 03-example-adfs-config.ps1
    web.vm.network "private_network", ip: "10.0.0.10"
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
      echo "10.0.0.2 adfs.example.com" >> /etc/hosts
    SHELL
  end
end
