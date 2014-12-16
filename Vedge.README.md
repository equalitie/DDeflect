Debian trafficserver setup instructions
========

If you don't want a special setup or care about how your v-edge is set up, have a standalone server that isn't running anything, or have a server that is running another webserver/service that you don't want to have your V-edge related to, follow these steps:

1. Run `apt-get install trafficserver`
2. Enable trafficserver in `/etc/default/trafficserver` by setting `TC_START=yes` (it is no by defalt)
3. Edit `/etc/trafficserver/records.config` and change `proxy.config.http.server_port` to whatever port you want and set `proxy.config.url_remap.pristine_host_hdr` to 0
4. Add the following line to `/etc/trafficserver/remap.config`: `map             http://$YOURHOSTNAME:$YOURPORT http://$YOURTEDGE.deflect.ca`
4.1 If you have received multiple T-edge names, you should enter multiple lines, replacing $YOURTEDGE with each of the T-edge names.
5. Restart trafficserver and your edge should start seeing requests for bundles

Generic reverse proxy setup instructions
========

All that is required for basic V-edge functionality is for a reverse proxy to be set up (on any port) to serve URLs containing your V-edge's hostname (For example myvedge1.deflect.ca) that are remapped to the T-edge (or T-edge list) that your V-edge is serving for.

V-edges must set a cache time of minimum 10 minutes for bundle objects. It can be longer if you please! Bundles will eventually be invalidated by rotation mechanisms so there is no need to store bundles indefinitely.

All incoming URLs will be of the format http://$YOUR_VEDGE_NAME:$YOUR_VEDGE_PORT/_bundle/$A_BUNDLE_HASH.

The remap to the T-edge can be via HTTP or HTTPS. HTTPS is prefered but because we cannot distribute certificates to V-edges the URLs served to users requesting bundles will always use HTTP.
