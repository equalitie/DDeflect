var daemon = require("daemonize2").setup({
    main: "/usr/bin/reaper",
    name: "reaper",
    pidfile: "/var/tmp/reaper/reaper.pid"
});

switch (process.argv[2]) {

    case "start":
        daemon.start();
        break;

    case "stop":
        console.log('here i am');
        daemon.stop();
        break;

    case "restart":
        daemon.stop();
        daemon.start();
        break;

    default:
        console.log("Usage: [start|stop|restart]");
}
