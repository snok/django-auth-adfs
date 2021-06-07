Demo
====
A ``Vagrantfile`` and example project are available to show what's needed to convert a Django project from form based
authentication to ADFS authentication.

Prerequisites
-------------
* A hypervisor like `virtualbox <https://www.virtualbox.org/>`__.
* A working `vagrant <https://www.vagrantup.com/>`__ installation. On Debian 11 (bullseye) if you use the `stock vagrant package <https://packages.debian.org/bullseye/vagrant>`__ you need to install these plugins::

    vagrant plugin install winrm
    vagrant plugin install winrm-fs
    vagrant plugin install winrm-elevated
    vagrant plugin install vagrant-reload

* The github repository should be cloned/downloaded in some directory.

This guide assumes you're using VirtualBox, but another hypervisor should also work.
If you choose to use another one, make sure there's a windows server 2019 vagrant box available for it.

Components
----------
The demo consists of 2 parts:

* A web server VM.
* A windows server 2019 VM.

The webserver will run Django and is reachable at ``http://web.example.com:8000``. The windows server will run a
domain controller and ADFS service.

Starting the environment
------------------------
Web server
~~~~~~~~~~
First we get the web server up and running.

#. Navigate to the directory where you cloned/downloaded the github repository.
#. Bring up the web server by running the command::

    vagrant up web

#. Wait as the vagrant box is downloaded and the needed software installed.
#. Next, SSH into the web server::

    vagrant ssh web

#. Once connected, start the Django project::

    cd /vagrant/demo/adfs
    python3 manage.py runserver 0.0.0.0:8000

you should now be able to browse the demo project by opening the page `http://localhost:8000 <http://localhost:8000>`__
in a browser. Pages requiring authentication wont work, because the ADFS server is not there yet.

.. note::

    There are 2 versions of the web example. One is a forms based authentication example, the other depends on ADFS.
    If you want to run the forms based example, change the path above to ``/vagrant/demo/formsbased``

ADFS server
~~~~~~~~~~~
The next vagrant box to start is the ADFS server. The scripts used for provisioning the ADFS server can be found in the
folder ``/vagrant`` inside the repository.

#. Navigate to the directory where you cloned/downloaded the github repository.
#. Bring up the ADFS server by running the command::

    vagrant up adfs

#. Wait as the vagrant box is downloaded and the needed software installed. **For this windows box, it takes a couple
   of coffees before it's done.**
#. Next, open window showing the login screen of the windows server. The login credentials are::

    username: vagrant
    password: vagrant

#. Once logged in, install a browser like Chrome of Firefox.
#. Next, in that browser on the windows server, verify you can open the page
   `http://web.example.com:8000 <http://web.example.com:8000>`__

In the AD FS management console, you can check how the example project is configured. The config is in the
**Application Groups** folder.

.. note::

    You wont be able to test the demo project from outside the windows machine because port 443 is not forwarded and
    name resolution of adfs.example.com won't work. You can workaround this by forwarding that port 443 from the guest
    to port 443 on your host and manually adding the right IP addresses in you hosts file.

.. note::

    Because windows server virtual boxes are rather rare on the vagrant cloud (they need to be rebuild every 180 days),
    it might be that the box specified in the ``Vagrantfile`` doesn't work anymore. If you replace it by another one
    that's just a vanilla windows server, it should work.

Using the demo
--------------
Once everything is up and running, you can click around in the very basic poll app that the demo is.

* The bottom of the page shows details about the logged in user.
* There are 2 users already created in the Active Directory domain. Both having the default password ``Password123``

    * ``bob@example.com`` which is a Django super user because he's a member of active directory group ``django_admins``.
    * ``alice@example.com`` which is a regular Django user.

* By default, only the page to vote on a poll requires you to be logged in.
* There are no questions by default. Create some in the admin section with user ``bob``.
* Compare the files in ``/vagrant/demo/formsbased`` to those in ``/vagrant/demo/adfs`` to see what was changed
  to enable ADFS authentication in a demo project.
