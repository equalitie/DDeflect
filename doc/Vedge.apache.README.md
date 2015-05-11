Debian instructions for Apache V-edge configuration
========

1. If you haven't already, install apache itself `apt-get install apache2`
2. Enable the cache and reverse proxy modules: `a2enmod cache cache_disk proxy`
3. Install the configuration file in the section below to `/etc/apache2/sites-available/ddeflect.conf`
4. Customise the config file as is needed - at a minimum, you'll need to change the DDeflecTEdge definition to represent the T-edge you've been assigned. DDeflectPath should be changed to represent the path you configured your V-edge to use when you signed up.
5. Run `a2ensite ddeflect`


Configuration file
--------
```

# - /path/to/cache should exist, ideally on its own partition, and should be
#   mounted 'noatime,data=writeback'. noatime elimates the need to update atime
#   on every read. data=writeback allows journal writes to be delayed also
#   increasing cache disk performance, but it will have less affect on ddeflect
#   than the noatime option, because ddeflect is relatively read-heavy.  The fs
#   should have at least nGb free - for now, finger in the air, 1gb.
#

# define the location on disk of the cache
Define CacheDir /var/cache/apache2/
# define the local DDeflect URI appendage
Define DDeflectPath /ddeflect
# define the upstream DDeflect TEdge dns name
Define DDeflectTEdge http://tedge.ddeflect.ca

# set the CacheRoot
CacheRoot ${CacheDir}

# enable the disk cache for /DDeflectPath
CacheEnable disk ${DDeflectPath}

# default is 1mb, using 5mb as bundles may exceed 1mb
CacheMaxFileSize 5000000

# as we do not use query strings, ignore them
CacheIgnoreQueryString On

# ignore client-side requests to bypass the cache
CacheIgnoreCacheControl On

# add the X-Cache header to determine hit vs miss
CacheHeader on

# enable the RewriteEngine
RewriteEngine On
# rewrite+proxy bundler URIs to the DDeflect TEdge, discarding any query string
RewriteRule ^${DDeflectPath}/_bundle/(.{128})$ ${DDeflectTEdge}/_bundle/$1 [P,QSD,DPI,L]
# send 404 to any other DDeflectPath/ URIs
RewriteRule ^${DDeflectPath}.*$ - [L,R=404]

# custom error documents for DDeflectPath
<Location ${DDeflectPath}>
ErrorDocument 404 "This is DDeflect 404 PlaceHolder"
ErrorDocument 502 "Bad Gateway DDeflect Error"
</Location>
```
