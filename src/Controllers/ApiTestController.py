from flask import jsonify

class ApiTestController:
    @staticmethod
    def test_api():
        result = {
            "status": "error",
            "message": "Working perfectly",
            "data": []
        }
        return jsonify(result)