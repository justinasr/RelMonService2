"""
Module that contains start of the program, tick scheduler and web APIs
"""
import logging
import json
import configparser
import os
import time
import inspect
from datetime import datetime
from flask import (
    Flask,
    render_template,
    request,
    session,
    make_response,
)
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_restful import Api
from jinja2.exceptions import TemplateNotFound
from apscheduler.schedulers.background import BackgroundScheduler
from mongodb_database import Database
from local.controller import Controller
from local.relmon import RelMon
from middlewares.auth import AuthenticationMiddleware


app = Flask(
    __name__, static_folder="./frontend/dist/static", template_folder="./frontend/dist"
)
api = Api(app)
scheduler = BackgroundScheduler()
controller = Controller()

# Handle redirections from a reverse proxy
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# OIDC client
# We require some environment variables to configure properly this component
# Instantiate the middleware inside the main function
auth: AuthenticationMiddleware = None
app.before_request(lambda: auth(request=request, session=session))


@app.route("/")
def index_page():
    """
    Return index.html
    """
    try:
        return render_template("index.html")
    except TemplateNotFound:
        response = "<script>setTimeout(function() {location.reload();}, 5000);</script>"
        response += "Webpage is starting, please wait a few minutes..."
        return response


@app.route("/api/create", methods=["POST"])
def add_relmon():
    """
    API to create a RelMon
    """
    if not is_user_authorized():
        return output_text({"message": "Unauthorized"}, code=403)

    relmon = json.loads(request.data.decode("utf-8"))
    if not relmon.get("name"):
        return output_text({"message": "No name"}, code=400)

    relmon["id"] = str(int(time.time()))
    relmon = RelMon(relmon)
    database = Database()
    if database.get_relmons_with_name(relmon.get_name()):
        return output_text(
            {"message": "RelMon with this name already exists"}, code=422
        )

    if database.get_relmon(relmon.get_id()):
        return output_text({"message": "RelMon with this ID already exists"}, code=422)

    controller.create_relmon(relmon, database, user_info_dict())
    controller_tick()
    return output_text({"message": "OK"})


@app.route("/api/reset", methods=["POST"])
def reset_relmon():
    """
    API to reset a RelMon
    """
    if not is_user_authorized():
        return output_text({"message": "Unauthorized"}, code=403)

    data = json.loads(request.data.decode("utf-8"))
    if "id" in data:
        controller.add_to_reset_list(str(int(data["id"])), user_info_dict())
        controller_tick()
        return output_text({"message": "OK"})

    return output_text({"message": "No ID"})


@app.route("/api/delete", methods=["DELETE"])
def delete_relmon():
    """
    API to delete a RelMon
    """
    if not is_user_authorized():
        return output_text({"message": "Unauthorized"}, code=403)

    data = json.loads(request.data.decode("utf-8"))
    if "id" in data:
        controller.add_to_delete_list(str(int(data["id"])), user_info_dict())
        controller_tick()
        return output_text({"message": "OK"})

    return output_text({"message": "No ID"})


@app.route("/api/get_relmons")
def get_relmons():
    """
    API to fetch RelMons from database
    """
    database = Database()
    args = request.args.to_dict()
    if args is None:
        args = {}

    page = int(args.get("page", 0))
    limit = int(args.get("limit", database.PAGE_SIZE))
    query = args.get("q")
    if query:
        query = query.strip()
        if query.lower() in (
            "new",
            "submitted",
            "running",
            "finishing",
            "done",
            "failed",
        ):
            query_dict = {"status": query.lower()}
            data, total_rows = database.get_relmons(
                query_dict=query_dict, page=page, page_size=limit
            )
        else:
            query_dict = {"_id": query}
            data, total_rows = database.get_relmons(
                query_dict=query_dict, page=page, page_size=limit
            )
            if total_rows == 0:
                query = "*%s*" % (query)
                # Perform case insensitive search
                query_dict = {
                    "name": {"$regex": query.replace("*", ".*"), "$options": "-i"}
                }
                data, total_rows = database.get_relmons(
                    query_dict=query_dict, page=page, page_size=limit
                )
    else:
        data, total_rows = database.get_relmons(page=page, page_size=limit)

    for relmon in data:
        relmon.pop("user_info", None)
        relmon["total_relvals"] = 0
        relmon["downloaded_relvals"] = 0
        relmon["compared_relvals"] = 0
        for category in relmon.get("categories"):
            relmon["total_relvals"] += len(category["reference"]) + len(
                category["target"]
            )
            for reference_target in ("reference", "target"):
                category["rerun"] = False
                category["%s_status" % (reference_target)] = {}
                category["%s_size" % (reference_target)] = 0
                for relval in category[reference_target]:
                    category["%s_size" % (reference_target)] += relval.get(
                        "file_size", 0
                    )
                    relmon_status = relval["status"]
                    if relmon_status not in category["%s_status" % (reference_target)]:
                        category["%s_status" % (reference_target)][relmon_status] = 0

                    if relmon_status != "initial":
                        relmon["downloaded_relvals"] += +1

                    if category["status"] == "done":
                        relmon["compared_relvals"] += 1

                    category["%s_status" % (reference_target)][relmon_status] += 1

    return output_text({"data": data, "total_rows": total_rows, "page_size": limit})


def output_text(data, code=200, headers=None):
    """
    Makes a Flask response with a plain text encoded body
    """
    resp = make_response(json.dumps(data, indent=1, sort_keys=True), code)
    resp.headers.extend(headers or {})
    resp.headers["Content-Type"] = "application/json"
    resp.headers["Access-Control-Allow-Origin"] = "*"
    return resp


@app.route("/api/edit", methods=["POST"])
def edit_relmon():
    """
    API for RelMon editing
    """
    if not is_user_authorized():
        return output_text({"message": "Unauthorized"}, code=403)

    relmon = json.loads(request.data.decode("utf-8"))
    relmon = RelMon(relmon)
    database = Database()
    existing_relmons_with_same_name = database.get_relmons_with_name(relmon.get_name())
    for existing_relmon_with_same_name in existing_relmons_with_same_name:
        if existing_relmon_with_same_name["id"] != relmon.get_id():
            return output_text(
                {"message": "RelMon with this name already exists"}, code=409
            )

    relmon_id = relmon.get_id()
    existing_relmon = database.get_relmon(relmon_id)
    if not relmon_id or not existing_relmon:
        return output_text({"message": "RelMon does not exist"}, code=404)

    controller.edit_relmon(relmon, database, user_info_dict())
    controller_tick()
    return output_text({"message": "OK"})


@app.route("/api/update", methods=["POST"])
def update_info():
    """
    API for jobs in HTCondor to notify about progress
    """
    user_data = session.get("user")
    login = user_data.get("username", "???")
    roles = user_data.get("roles", [])
    valid_roles = set("heartbeat")

    logger = logging.getLogger("logger")
    authorized = bool(set(roles) & valid_roles)
    if not authorized:
        logger.warning('Not letting through user "%s" to do update', login)
        return output_text({"message": "Unauthorized"}, code=403)

    data = json.loads(request.data.decode("utf-8"))
    database = Database()
    relmon = database.get_relmon(data["id"])
    if not relmon:
        return output_text({"message": "Could not find"})

    old_status = relmon.get("status")
    relmon["categories"] = data["categories"]
    relmon["status"] = data["status"]
    logger.info(
        "Update for %s (%s). Status is %s",
        relmon["name"],
        relmon["id"],
        relmon["status"],
    )
    database.update_relmon(RelMon(relmon))
    if relmon["status"] != old_status:
        for job in scheduler.get_jobs():
            job.modify(next_run_time=datetime.now())

    return output_text({"message": "OK"})


@app.route("/api/tick")
def controller_tick():
    """
    API to trigger a controller tick
    """
    if not is_user_authorized():
        return output_text({"message": "Unauthorized"}, code=403)

    for job in scheduler.get_jobs():
        job.modify(next_run_time=datetime.now())

    return output_text({"message": "OK"})


@app.route("/api/user")
def user_info():
    """
    API for user info
    """
    return output_text(user_info_dict())


@app.route("/api", defaults={"_path": ""})
@app.route("/api/<path:_path>")
def api_documentation(_path):
    """
    Endpoint for API documentation HTML
    """
    docs = {}
    base = os.path.dirname(os.path.realpath(__file__))
    for rule in app.url_map.iter_rules():
        endpoint = rule.rule
        func = app.view_functions[rule.endpoint]
        methods = sorted(list(rule.methods & {"GET", "PUT", "POST", "DELETE"}))
        if not methods or "api" not in endpoint:
            continue

        docs[endpoint] = {
            "doc": func.__doc__.strip(),
            "methods": methods,
            "file": inspect.getfile(func).replace(base, "").strip("/"),
            "line": inspect.getsourcelines(func)[1],
        }

    return render_template("api_documentation.html", docs=docs)


def user_info_dict():
    """
    Get user name, login, email and authorized flag from request headers
    """
    user_data = session.get("user")
    fullname = user_data.get("fullname", "")
    login = user_data.get("username", "")
    email = user_data.get("email", "")
    authorized_user = is_user_authorized()
    return {
        "login": login,
        "authorized_user": authorized_user,
        "fullname": fullname,
        "email": email,
    }


def is_user_authorized():
    """
    Return whether user is a member of administrators e-group
    """
    user_data = session.get("user")
    roles = user_data.get("roles", [])
    return "administrator" in roles


def tick():
    """
    Trigger controller to perform a tick
    """
    controller.tick()


def setup_console_logging():
    """
    Setup logging to console
    """
    logging.basicConfig(
        format="[%(asctime)s][%(levelname)s] %(message)s", level=logging.INFO
    )


def get_config(mode):
    """
    Get config as a dictionary
    Based on the mode - prod or dev
    """
    config = configparser.ConfigParser()
    config.read("config.cfg")
    config = dict(config.items(mode))
    logging.info("Config values:")
    for key, value in config.items():
        if key in (
            "ssh_credentials",
            "database_auth",
            "oidc_client_id",
            "oidc_client_secret",
            "secret_key",
            "oauth_heartbeat_client_id",
            "oauth_heartbeat_client_secret",
        ):
            logging.info("  %s: ******", key)
        else:
            logging.info("  %s: %s", key, value)

    return config


def parse_bool(value: str | None) -> bool:
    """
    Parse a boolean value from a string.
    If value is None or if it is not equal to "true" string
    It will return False.
    """
    if value and str(value).lower() == "true":
        return True
    return False


def set_app(mode: str = "dev", debug: bool = True) -> tuple[str, int, bool]:
    """
    Set Flask appplication configuration via config.cfg file
    Parameters
    ----------
    mode: str
        Deployment mode: "dev" or "prod"
    debug: bool
        Logging mode: DEBUG
    Returns
    ----------
    tuple[str, int, bool]
        Host name, port number and debug mode (for logging and Werkzeug server)
    """
    global auth

    setup_console_logging()
    logger = logging.getLogger("logger")
    logger.info("Loading configuration from config.cfg file using mode: %s", mode)
    config = get_config(mode)

    database_auth = config.get("database_auth")
    logger.info("Database credentials loaded from file: %s", database_auth)
    if database_auth:
        Database.set_credentials_file(database_auth)

    executor: str = "processpool"
    logger.info("Including executor: %s to scheduler", executor)
    scheduler.add_executor(executor)

    # Flask app: Secret key
    logger.info("Setting Flask app secret key")
    secret_key = config.get("secret_key")
    app.secret_key = secret_key

    # Instantiate the auth middleware
    logger.info("Creating authetication middleware")
    oidc_client_id = config.get("oidc_client_id")
    oauth_heartbeat_client_id = config.get("oauth_heartbeat_client_id")
    oidc_client_secret = config.get("oidc_client_secret")
    auth = AuthenticationMiddleware(
        app=app,
        client_id=oidc_client_id,
        client_secret=oidc_client_secret,
        home_endpoint="index_page",
        valid_audiences=[oidc_client_id, oauth_heartbeat_client_id],
    )
    logger.info("Authentication middleware: %s", auth)

    if not debug or os.environ.get("WERKZEUG_RUN_MAIN") == "true":
        logger.info("Setting controller and interval")
        controller.set_config(config)
        scheduler.add_job(
            tick, "interval", seconds=int(config.get("tick_interval")), max_instances=1
        )

    # Deployment configuration
    host = config.get("host")
    port = config.get("port")
    logger.info("Deployment mode: %s", mode)
    logger.info("Debug mode: %s", debug)
    logger.info("Host: %s, Port: %s", host, port)
    return host, port, debug
