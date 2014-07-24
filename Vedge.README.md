Debian setup instructions
========
# Run `apt-get install trafficserver`
# Enable trafficserver in `/etc/default/trafficserver` by setting `TC_START=yes` (it is no by defalt)
# Edit `/etc/trafficserver/records.config` and change `proxy.config.http.server_port` to whatever port you want and set `proxy.config.url_remap.pristine_host_hdr` to 0
# Add the following line to `/etc/trafficserver/remap.config`: `map             http://$YOURHOSTNAME:$YOURPORT http://$YOURTEDGE.deflect.ca`
# Restart trafficserver and your edge should start seeing requests for bundles
