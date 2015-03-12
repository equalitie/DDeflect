Debian trafficserver setup instructions
========

If you don't want a special setup or care about how your v-edge is set up, have a standalone server that isn't running anything, or have a server that is running another webserver/service that you don't want to have your V-edge related to, follow these steps:

1. Run `apt-get install trafficserver`
2. Enable trafficserver in `/etc/default/trafficserver` by setting `TC_START=yes` (it is no by defalt)
3. Edit `/etc/trafficserver/records.config` and change `proxy.config.http.server_port` to whatever port you want and set `proxy.config.url_remap.pristine_host_hdr` to 0
4. Add the following line to `/etc/trafficserver/remap.config`: `map             http://$YOURHOSTNAME:$YOURPORT http://$YOURTEDGE.deflect.ca`
 * If you have received multiple T-edge names, you should enter multiple lines, replacing $YOURTEDGE with each of the T-edge names.
5. Enable bundle caching in your Vedge by adding the following line to `/etc/trafficserver/cache.config`, substituting your hostname as appropriate: `url_regex=^http://$YOURHOSTNAME/_bundle/.*$ ttl-in-cache=12h pin-in-cache=12h`
6. Restart trafficserver and your edge should start seeing requests for bundles
