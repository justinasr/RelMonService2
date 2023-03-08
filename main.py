"""
Flask app entrypoint
"""
import logging
import os
from app import app, set_app, parse_bool, scheduler


def main():
    """
    Main function,
    Start Flask web server
    """
    debug = parse_bool(os.environ.get("DEBUG", True))
    mode = os.environ.get("MODE", "dev")
    host, port, debug = set_app(mode=mode, debug=debug)
    logger = logging.getLogger()
    scheduler.start()
    logger.info("Will run on %s:%s", host, port)
    if os.environ.get("WERKZEUG_RUN_MAIN") != "true":
        # Do only once, before the reloader
        pid = os.getpid()
        logger.info("PID: %s", pid)
        with open("relmonservice.pid", "w") as pid_file:
            pid_file.write(str(pid))

    app.run(host=host, port=port, debug=debug, threaded=True)
    scheduler.shutdown()


if __name__ == "__main__":
    main()
