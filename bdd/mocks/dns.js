var edges = ['edge1.ddeflect', 'edge2.ddeflect'];

exports.resolve = function(host) {
  switch(host) {
    case 'activist.org':
      return edges[0];
    case 'edges.ddeflect':
      return edges;
    case 'http://activist.org':
      return 'http://localhost:3550/bundled.html';
    case 'good':
      return 'http://localhost:3550/good';
    case 'bad':
      return 'http://localhost:3550/bad';
    case 'offline':
      return 'http://localhost:3550/timeout';
    case 'notify':
      return 'http://localhost:3550/notify.html';
    default:
      throw 'unknown ' + host;
  }
};

