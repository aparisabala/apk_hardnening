import eventlet
eventlet.monkey_patch()
import os
import sys
from dotenv import load_dotenv
load_dotenv()

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, jsonify, request
from src.Controllers.APKController import APKController
from src.Lib.Hardening.APKTool import APKTool
from src.Lib.Hardening.APKProcessor import APKProcessor
from flask_socketio import SocketIO
from src.Lib.Socket.emitter import init_socketio

app = Flask(__name__)

socketio = SocketIO(app, cors_allowed_origins="*", async_mode="eventlet") 
init_socketio(socketio)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Config from env
BASE_URL = os.getenv("HARDENING_BASE_URL", "http://localhost:8000")
DOWNLOAD_DIR = os.getenv("HARDENING_DOWNLOAD_DIR", os.path.join(BASE_DIR, "downloads"))

apktool_path = os.path.join(BASE_DIR, "./apktool/Apktool/apktool_2.9.2.jar")
jobs_dir = os.path.join(BASE_DIR, "jobs")

os.makedirs(jobs_dir, exist_ok=True)
os.makedirs(DOWNLOAD_DIR, exist_ok=True)

apktool = APKTool(jar_path=apktool_path)

processor = APKProcessor(
    jobs_dir=jobs_dir,
    download_dir=DOWNLOAD_DIR,
    apktool=apktool,
    base_url=BASE_URL
)

apk_controller = APKController(processor)

@app.route("/", methods=["GET"])
def home():
    return "404 not found - 1.1.3"

@app.route("/harden", methods=["POST"])
def harden():
    return apk_controller.harden_background()

@app.route("/job-completed", methods=["POST"])
def jobStatus():
    data = request.get_json(silent=True) or {}
    socketio.emit('job_completed', data)
    return jsonify({"status": "ok"}), 200

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=8000, debug=True)