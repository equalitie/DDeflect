var webdriver = require('selenium-webdriver'), assert = require('assert'), Yadda = require('yadda');

var bundler = require('../mocks/bundler'), dns = require('../mocks/dns'), util = require('./util');

module.exports = (function() {

  var dictionary = new Yadda.Dictionary()
    .define('NUM', /(\d+)/);

  var library = new Yadda.localisation.English.library(dictionary)

// Scenario: Get web site address

    .when("I request $HOST from DNS", function(host, next) {
      context.hdig = dns.resolve(host);

      next();
    })

    .then('I should receive an IP address', function(next) {
      assert(context.hdig.length > 0);
      next();
    })

    .then('it should be a trusted edge', function(next) {
      var edig = dns.resolve('edges.ddeflect');
      assert(edig.indexOf(context.hdig) > -1);
      next();
    })

// Scenario: Get web index

    .when('I request $PAGE', function(page, next) {
      var loc = dns.resolve(page);
      this.driver.get(loc).then(next);
    })

    .then('it should contain unbundler code', function(next) {
      this.driver.findElement(webdriver.By.css('#unbundler')).then(function(form) {
       assert.ok(form);
       next();
      });
    })

    .then('a link to bundled content on a v-edge', function(next) {
      this.driver.findElement(webdriver.By.css('#bundle')).then(function(form) {
       assert.ok(form);
       next();
      });
    })

// Scenario: Get web assets

    .when('I request the link to bundled content from $TYPE v-edge', function(type, next) {
      delete context.downloadContent;
      delete context.downloadStatus
      util.download(dns.resolve(type), function(err, contents) {
        if (err) {
          context.downloadError = err;
        } else {
          context.downloadContent = contents.toString().trim();
        }
        next();
      });
    })

    .then('I should receive a valid encrypted bundle', function(next) {
      assert(bundler.isBundle(context.downloadContent));
      next();
    })

    .then('it should contain valid web content', function(next) {
      assert(bundler.unbundle(context.downloadContent) == '<h1>This is valid content</h1>');
      next();
    })

// Scenario: Bad v-edge

    // I request the link to bundled content from the malicious v-edge

    .then('I should receive a invalid encrypted bundle', function(next) {
      assert(!bundler.isBundle(context.downloadContent));
      next();
    })

    .then('I should notify the trusted edge', function(next) {
      this.driver.get(dns.resolve('notify')).then(next);
    })

    .then('I should receive a report response', function(next) {
      this.driver.findElement(webdriver.By.css('#response')).then(function(form) {
        assert.ok(form);
        next();
      });
    })

// Scenario: v-edge times out

    // I request the link to bundled content from the offline v-edge

    .then('it takes longer than $NUM seconds', function(num, next) {
        assert(context.downloadError == 'timeout');
        next();
    });
    // I should notify the trusted edge

    // I should receive a report response

    // a link to bundled content on a v-ege

    return library;
})();

