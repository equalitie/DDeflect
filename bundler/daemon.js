var daemon = require("daemonize2").setup({
    main: "/home/bill/Documents/eq_projects/DDeflect/bundler/src/bundler.js",
    name: "bundler",
    pidfile: "bundler.pid"
});

switch (process.argv[2]) {

    case "start":
        daemon.start();
        break;

    case "stop":
        daemon.stop();
        break;

    case "restart":
        daemon.stop();
        daemon.start();
        break;

    default:
        console.log("Usage: [start|stop|restart]");
}
