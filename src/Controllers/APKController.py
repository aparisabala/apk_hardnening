import os
import time
import uuid
import shutil
import subprocess
from flask import Flask, request, jsonify
from src.Lib.Hardening.APKBatchProcessor import APKBatchProcessor
class APKController:
    def __init__(self, processor: APKBatchProcessor):
        self.processor = processor

    def batch(self):
        data = request.json if request.is_json else {}

        apk_urls = data.get("apks", [])
        interval = int(data.get("interval", 8))

        if not apk_urls:
            return jsonify({"error": "No APK URLs provided"}), 400

        results = self.processor.process_batch(apk_urls, interval)
        return jsonify({"status": "completed", "results": results})

    def home(self):
        return "Class-Based Flask APK Service is running."