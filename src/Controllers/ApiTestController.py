from flask import jsonify

class ApiTestController:
    def test_api(self):
        return jsonify({"status": "test_success", "message": "API is working"})