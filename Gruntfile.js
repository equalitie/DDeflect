module.exports = function(grunt) {
  var cwd = require("path").resolve(__dirname);
  var srcFiles = [
    '**.js',
  ];

  grunt.initConfig({
    jshint: {
      files: srcFiles
    },
    mochaTest: {
      devUnitTest: {
        options: {
          reporter: 'spec'
        },
        src: ['test/*-test.js']
      },
    },
    /*
    docco: {
      docs: {
        src: srcFiles,
        dest: 'docs/annotated-source'
      }
    },
    */
    plato: {
      ddeflect: {
        files: {
          'reports': srcFiles
        }
      }
    },
    watch: {
      dev: {
        files: [
          '<%= jshint.files %>'
        ],
        tasks: ['jshint', 'mochaTest:devUnitTest']
      },
      devUnit: {
        files: [
          '<%= jshint.files %>',
          '*.js',
          '**/*.js',
          'test/!(outfile)'
        ],
        tasks: ['jshint', 'mochaTest:devUnitTest']
      },
    }
  });

  // load the relevant plugins
  grunt.loadNpmTasks('grunt-contrib-jshint');
  grunt.loadNpmTasks('grunt-contrib-watch');
  grunt.loadNpmTasks('grunt-docco2');
  grunt.loadNpmTasks('grunt-plato');
  grunt.loadNpmTasks('grunt-mocha-test');

  // Default task(s).
  grunt.registerTask('default', ['jshint', 'mochaTest', 'plato']);
  grunt.registerTask('sanity-test', ['jshint', 'mochaTest:configTest', 'mochaTest:devUnitTest']);

};
