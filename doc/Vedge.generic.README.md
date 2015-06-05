Generic reverse proxy setup instructions
========

All that is required for basic V-edge functionality is for a reverse proxy to be set up (on any port) to serve URLs containing your V-edge's hostname (For example myvedge1.deflect.ca) that are remapped to the T-edge (or T-edge list) that your V-edge is serving for.

V-edges must set a cache time of minimum 2 hours for bundle objects. It can be longer - the longer the better, within reason! Bundles will eventually be invalidated by rotation mechanisms so there is no need to store bundles indefinitely.

All incoming URLs will be of the format http://$YOUR_VEDGE_NAME:$YOUR_VEDGE_PORT/_bundle/$A_BUNDLE_HASH.

The remap to the T-edge can be via HTTP or HTTPS. HTTPS is prefered but because we cannot distribute certificates to V-edges the URLs served to users requesting bundles will always use HTTP.
