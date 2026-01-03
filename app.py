import os
import sys
import asyncio
import threading

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from flask import Flask
from src.Controllers.ApiTestController import ApiTestController
from src.Controllers.APKController import APKController
from src.Lib.Hardening.APKTool import APKTool
from src.Lib.Hardening.APKBatchProcessor import APKBatchProcessor
from flask_sock import Sock


app = Flask(__name__)
sock = Sock(app)
connected_clients = set()

bg_loop = asyncio.new_event_loop()

def start_loop():
    asyncio.set_event_loop(bg_loop)
    bg_loop.run_forever()

threading.Thread(target=start_loop, daemon=True).start()


def schedule_coro(coro):
    return asyncio.run_coroutine_threadsafe(coro, bg_loop)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

apktool_path = os.path.join(BASE_DIR, "./apktool/Apktool/apktool_2.6.1.jar")
jobs_dir = os.path.join(BASE_DIR, "jobs")
download_dir = os.path.join(BASE_DIR, "downloads")   

os.makedirs(jobs_dir, exist_ok=True)
os.makedirs(download_dir, exist_ok=True)

apktool = APKTool(jar_path=apktool_path)

processor = APKBatchProcessor(
    jobs_dir=jobs_dir,
    download_dir=download_dir,
    apktool=apktool
)

apk_controller = APKController(processor)
api_test_controller = ApiTestController()


@app.route("/", methods=["GET"])
def home():
    return "404 not found"

@app.route("/test", methods=["POST"])
def test_route():
    return api_test_controller.test_api()

app.add_url_rule("/batch", view_func=apk_controller.batch,  methods=["POST"])

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
