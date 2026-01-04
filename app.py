import os
import sys
from dotenv import load_dotenv
load_dotenv()

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, jsonify
from src.Controllers.APKController import APKController
from src.Lib.Hardening.APKTool import APKTool
from src.Lib.Hardening.APKProcessor import APKProcessor

app = Flask(__name__)

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
    return "404 not found - 1.0"

@app.route("/harden", methods=["POST"])
def harden():
    return apk_controller.harden_background()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)