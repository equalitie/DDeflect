# Reaper

Programmed by Nadim "*the Dream*" Kobeissi  

## Installation
1. [Install PhantomJS](http://phantomjs.org/download.html) on your system.  
2. ```cd``` to the bundler directory
3. Run ```npm install```  
4. Run ```node bundler```  

## Test and build a debian package with grunt
0. ``npm install grunt-debian-package`` https://www.npmjs.org/package/grunt-debian-package
1. Install grunt locally: ``npm install grunt --save-dev``
2. And all dependencies: ``npm install``
3. Run jshint for style checks: ``grunt test``
4. Build debian package: ``grunt debian`` - this is still work in progress but spits out a .deb under tmp
