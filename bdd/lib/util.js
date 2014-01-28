// Directly downloads content over http, timing out after 5 seconds

exports.download = function(loc, callback) {
  var http = require('http');

  request = http.get(loc, function(res){
    var body = '';
    res.on('data', function(data) {
      body += data;
    });
    res.on('end', function() {
      callback(null, body);
    });
    res.on('error', function(e) {
      callback(e);
    });
  });
  request.shouldKeepAlive = false;
  request.on('socket', function (socket) {
    socket.setTimeout(5000);  
    socket.on('timeout', function() {
      request.abort();
    });
  });
  request.on('error', function(error) {
    callback('timeout');
  });
};

