#!/usr/bin/env python3
"""
Run the following commands (bc. gists don't allow directories)
pip install flask django dj-database-url psycopg2
mkdir -p app/migrations
touch app/__init__.py app/migrations/__init__.py
mv models.py app/
python manage.py makemigrations
python manage.py migrate
DJANGO_SETTINGS_MODULE=settings python app.py
visit http://localhost:5307
See https://docs.djangoproject.com/en/1.11/topics/settings/#either-configure-or-django-settings-module-is-required for documentation
"""
import argparse
import logging
import pathlib
import telnetlib
from typing import *

import os
from flask import Flask, send_file, render_template, request, jsonify, redirect

parentdir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
os.sys.path.insert(0, parentdir)
import config_parser
from webserver.fexm_data_analyzer import FexmDataAnalyzer

logging.basicConfig()
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

app = Flask(__name__)

CRASH_ORDERING = ["EXPLOITABLE", "PROBABLY_EXPLOITABLE", "UNKNOWN", "PROBABLY_NOT_EXPLOITABLE", "NOT_EXPLOITABLE", "",
                  None]
CRASH_ORDERING.reverse()
REPEAT_COLLECT_TIME = 5 * 60  # Repeat collect every 5 Min

spawned_ports = set()  # typ: Set[int]


@app.route("/fexm/<package_name>/<binary_name>/crashes/<crashes_filename>", methods=['GET'])
def download_crash(package_name: str, binary_name: str, crashes_filename: str):
    if crashes_filename.startswith(".") or crashes_filename.startswith("/"):
        raise ValueError("Illegal chars in crashes_filename.")

    fexm_analyzer = app.config["analyzer"]
    print(fexm_analyzer.package_dict[package_name].binaries)
    binary = fexm_analyzer.package_dict[package_name].binaries[binary_name]  # type: fexm_analyzer.Binary
    crashes_fullpath = pathlib.Path(os.path.join(binary.fuzz_data_directory, binary.package,
                                                 binary.crashes_dir))
    crash_path = (crashes_fullpath / crashes_filename).resolve()

    if crashes_fullpath not in crash_path.parents or pathlib.Path(
            fexm_analyzer.configuration_dir) not in crash_path.parents:
        raise ValueError("Access outside configuration/crashes dir!")
    return send_file(str(crash_path))


@app.route("/fexm/<package_name>/<binary_name>/timewarp", strict_slashes=False, methods=['GET'])
def timewarp(package_name: str, binary_name: str):
    fexm_analyzer = app.config["analyzer"]
    binary = fexm_analyzer.package_dict[package_name].binaries[binary_name]
    binary.refresh_fuzz_stats()
    timewarp_data = binary.start_timewarp(fexm_analyzer=fexm_analyzer)

    spawned_ports.add(timewarp_data["cnc_raw"])

    if request.is_xhr:  # accept_mimetypes.is_xhr:
        return jsonify(timewarp_data)
    else:
        return render_template("timewarp.html", binary_data=binary, timewarp_data=timewarp_data)


@app.route("/fexm/<package_name>/<binary_name>/timewarp/start_fuzzing/<port>", strict_slashes=False, methods=['GET'])
def tw_start_fuzzing(package_name: str, binary_name: str, port: Union[str, int]) -> None:
    port = int(port)
    if port not in spawned_ports:
        raise ValueError("Invalid port provided.")

    spawned_ports.remove(port)
    with telnetlib.Telnet("localhost", int(port)) as t:
        t.write(b"F\n")

    return redirect("/fexm/{}".format(package_name))


@app.route("/fexm/<package_name>/<binary_name>", strict_slashes=False, methods=['GET'])
def binary_detail(package_name: str, binary_name: str):
    referrer = request.headers.get("Referer")  # type: Optional[str]
    message = ""
    if referrer and referrer.lower().endswith("/fexm/{}/{}/timewarp".format(package_name, binary_name)):
        message = "TimeWarp Fuzzing Started!"

    fexm_analyzer = app.config["analyzer"]
    binary = fexm_analyzer.package_dict[package_name].binaries[binary_name]
    binary.refresh_fuzz_stats()
    return render_template("crashes.html", binary_data=binary, message=message)


@app.route("/fexm/<package_name>", methods=['GET'])
def package_detail(package_name: str):
    fexm_analyzer = app.config["analyzer"]
    fexm_analyzer.refresh()
    return render_template("package_detail.html", package_data=fexm_analyzer.package_dict[package_name])


@app.route("/analyze_crashes", strict_slashes=False)
def analyze():
    fexm_analyzer = app.config["analyzer"]
    fexm_analyzer.analyze()
    return jsonify({"success": True})


@app.route("/refresh_data", strict_slashes=False)
def refresh_data():
    fexm_analyzer = app.config["analyzer"]
    fexm_analyzer.refresh()
    return jsonify({"success": True})


@app.route("/")
@app.route("/fexm", strict_slashes=False)
def index():
    fexm_analyzer = app.config["analyzer"]
    fexm_analyzer.refresh()
    return render_template('index.html', data_list=fexm_analyzer.package_dict.values())


@app.route('/wstelnet', strict_slashes=False)
def wstelnet():
    return render_template('wstelnet.html')


def listen(host: str, port: int, config: Dict[str, Any]):
    app.config["fuzzer_config"] = config
    configuration_dir = config["out_dir"]
    base_image = config["base_image"]

    app.config["analyzer"] = FexmDataAnalyzer(configuration_dir, base_image)

    logger.info("Listening on {}:{}".format(host, port))
    app.run(host=host, port=int(port), debug=True, use_reloader=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Start the webserver')
    parser.add_argument("-c", "--config", help="The configuration file used for the fuzzer", type=str, required=True)
    parser.add_argument("-p", "--port", nargs="?", default=5307, type=int, help="Port to listen on")
    parser.add_argument("-l", "--host", nargs="?", default="0.0.0.0", type=str, help="Listening host")
    args = parser.parse_args()

    config = config_parser.load_config(args.config)
    listen(args.host, args.port, config)
