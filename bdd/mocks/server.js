var express = require('express');
var app = express();
var delay = 25000;

app.use(express.static(__dirname + '/public'));

app.listen(process.env.PORT || 3550);

app.get('/timeout', function(req, res){
  setTimeout(function() { res.send('after ' + delay + 'ms'); }, delay);
});
