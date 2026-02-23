from flask import request, jsonify
import os
from src.Lib.Socket.emitter import emit
from src.Lib.Hardening.Job import Job


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
        id = data.get("id")
        domain = data.get("service_domain")
        file_name = data.get("file_name")
        package_name_method = data.get("package_name_method")
        package_name = data.get("package_name")
        # Added for version injection
        current_version = data.get("current_version")
        app_name = data.get("name")
        apk_key = data.get("apk_key")
        op_call_back = data.get("op_call_back")

        if not apk_url:
            return jsonify({"status": "failed", "error": "apk_url is required"}), 400
        if not callback_url:
            return jsonify({"status": "failed", "error": "callback_url is required"}), 400
        if not id:
            return jsonify({"status": "failed", "error": "id required"}), 400
        if not domain:
            return jsonify({"status": "failed", "error": "domain required"}), 400
        if not file_name:
            return jsonify({"status": "failed", "error": "File name required"}), 400

        if not package_name_method:
            return jsonify({"status": "failed", "error": "Package name Method required"}), 400

        # Create Job object
        job = Job(
            apk_url=apk_url,
            callback_url=callback_url,
            id=id,
            domain=domain,
            file_name=file_name,
            package_name_method=package_name_method,
            package_name=package_name,
            current_version=current_version,
            app_name=app_name,
            apk_key=apk_key,
            op_call_back=op_call_back,
        )

        job_id = self.processor.start_background_hardening(job)
        response = {
            "status": "accepted",
            "job_id": job_id,
            "id": id,
            "message": "Hardening started in background. You will receive result via callback."
        }
        emit('job_accepted', response)
        return jsonify(response), 202
