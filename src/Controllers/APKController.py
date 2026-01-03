from threading import Thread
from flask import request, jsonify
import os

class APKController:
    def __init__(self, processor):
        self.processor = processor

    def harden_background(self):
        data = request.get_json(silent=True) or {}

        # API key security
        required_key = os.getenv("HARDENING_API_KEY")
        provided_key = data.get("api_key") or request.headers.get("X-API-Key")
        if required_key and provided_key != required_key:
            return jsonify({"status": "failed", "error": "Unauthorized"}), 401

        apk_url = data.get("apk_url")
        callback_url = data.get("callback_url")

        if not apk_url:
            return jsonify({"status": "failed", "error": "apk_url is required"}), 400
        if not callback_url:
            return jsonify({"status": "failed", "error": "callback_url is required"}), 400

        job_id = self.processor.start_background_hardening(apk_url, callback_url)

        return jsonify({
            "status": "accepted",
            "job_id": job_id,
            "message": "Hardening started in background. You will receive result via callback."
        }), 202