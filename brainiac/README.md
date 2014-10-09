brainiac
========

Mimicking Brains with Ansible

Requirements
--------

Nodes require python-apt.

Runs under Ansible 1.6 or later.

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
