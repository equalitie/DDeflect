// Mock bundler for prototype tests

exports.isBundle = function(contents) {
  return contents && contents.trim() == 'bundle';
};

exports.unbundle = function(content) {
  return '<h1>This is valid content</h1>';
};

