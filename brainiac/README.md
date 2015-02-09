brainiac
========

Mimicking Brains with Ansible

Requirements
--------

Nodes require python-apt.

Runs under Ansible 1.6 or later. 

Requires the following packages:
* ```redis-server```
* ```python-redis```
* ```sshpass```

Requires Redis to be running locally.

DIY
--------

Files that need to be present that aren't in the repo:
* An SSH key named $user.pub for any users listed in *deflect.yml*, stored in the `sensitive_files` directory
* An SSH key for statistics collecting named `trafficserver_id_rsa.pub`, stored in the `sensitive_files` directory
* A generic SSL certificate, chain and key used as a fallback for sites with no SSL cert, stored in `roles/trafficserver/files/`, with filename specified in *deflect.yml*.

* Install ansible and redis-server and start the Redis server running
 locally.

* Configure hosts.yml to include your T-edges, V-edges and optionally
a controller. By default "distributed.deflect.ca" is the T-edge
nodegroup in this file.

* Configure an origin via *clients.yml*

* Create a general SSH keypair for your ATS installs and store it somewhere. Change the `sensitive_files` variable in *deflect.yml* to reflect this location. This can be the same as ```trafficserver_id_rsa.pub``` if needs be. 

* Configure any voluntary edges via edges.yml.

* Run `ansible-playbook site.yml`

Configuration
--------
*clients.yml*

clients.yml is used to configure sites to be protected by
DDeflect. Configure the site's attributes from the rather
straightforward keys in the remap dict.

*hosts.yml*

hosts.yml is used to configure groups of hosts and the controller. The
controller group is for DNS etc management, the other groups are
groups that correspond to the `dnets` variable in clients.yml.

*deflect.yml*

If you're doing a full DNS setup, you can use deflect.yml to configure
your hidden primary.

*edges.yml*

This file is used to configure V-edges. Only the keys for the `vedges`
dict and the port value are currently used.
