"""
Module that contains start of the program, tick scheduler and web APIs
"""
import logging
import json
import os
import time
import inspect
from datetime import datetime
from flask import (
    Flask,
    session,
    render_template,
    request,
    make_response,
)
from flask_restful import Api
from jinja2.exceptions import TemplateNotFound
from apscheduler.schedulers.background import BackgroundScheduler
from core_lib.middlewares.auth import AuthenticationMiddleware, UserInfo
from mongodb_database import Database
from local.controller import Controller
from local.relmon import RelMon
from environment import (
    TICK_INTERVAL,
    HOST,
    PORT,
    DEBUG,
    SECRET_KEY,
    ENABLE_AUTH_MIDDLEWARE,
)


app = Flask(
    __name__, static_folder="./frontend/dist/static", template_folder="./frontend/dist"
)
api = Api(app)
if ENABLE_AUTH_MIDDLEWARE:
    app.secret_key = SECRET_KEY
    auth: AuthenticationMiddleware = AuthenticationMiddleware(app=app)
    app.before_request(
        lambda: auth.authenticate(request=request, flask_session=session)
    )
scheduler = BackgroundScheduler()
controller = Controller()


def get_groups_from_headers() -> list[str]:
    """
    Retrieves the list of e-groups sent via Adfs-Group header
    """
    groups = [
        x.strip().lower() for x in request.headers.get("Adfs-Group", "???").split(";")
    ]
    return groups


def get_roles() -> list[str]:
    """
    Retrieves the list of authorized roles/groups
    """
    user_data: UserInfo | None = session.get("user")
    if user_data:
        return user_data.roles
    return get_groups_from_headers()


def user_info_dict():
    """
    Get user name, login, email and authorized flag from request headers
    """
    user_data: UserInfo = session.get("user")
    if user_data:
        return {
            "login": user_data.username,
            "authorized_user": is_user_authorized(),
            "fullname": user_data.fullname,
            "email": user_data.email,
        }
    fullname = request.headers.get("Adfs-Fullname", "")
    login = request.headers.get("Adfs-Login", "")
    email = request.headers.get("Adfs-Email", "")
    return {
        "login": login,
        "authorized_user": is_user_authorized(),
        "fullname": fullname,
        "email": email,
    }


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
    authorized_roles: set[str] = set(["cms-pdmv-serv"])
    user_roles: set[str] = set(get_roles())
    logger = logging.getLogger("logger")
    user_data: dict[str, str] = user_info_dict()
    if bool(user_roles & authorized_roles) == False:
        logger.warning('Not letting through user "%s" to do update', user_data["login"])
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


def is_user_authorized() -> bool:
    """
    Return whether user is a member of administrators e-group
    """
    authorized_roles: set[str] = set(["cms-ppd-pdmv-val-admin-pdmv", "cms-pdmv-serv"])
    user_roles: set[str] = set(get_roles())
    return bool(user_roles & authorized_roles)


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


def main():
    """
    Main function, parse arguments, create a controller and start Flask web server
    """
    debug = DEBUG
    host = HOST
    port = PORT

    setup_console_logging()
    logger = logging.getLogger("logger")
    scheduler.add_executor("processpool")
    if not debug or os.environ.get("WERKZEUG_RUN_MAIN") == "true":
        controller.set_config()
        scheduler.add_job(tick, "interval", seconds=TICK_INTERVAL, max_instances=1)

    scheduler.start()
    logger.info("Will run on %s:%s", host, port)
    app.run(host=host, port=port, debug=debug, threaded=True)
    scheduler.shutdown()


if __name__ == "__main__":
    main()
