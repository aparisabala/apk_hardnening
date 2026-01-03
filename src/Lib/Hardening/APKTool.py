import os
import time
import uuid
import shutil
import subprocess
from flask import Flask, request, jsonify

class APKTool:
    def __init__(self, jar_path):
        self.jar_path = jar_path

    def run(self, command):
        try:
            result = subprocess.run(
                command,
                shell=True,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            return result.stdout + "\n" + result.stderr
        except Exception as e:
            return str(e)

    def decompile(self, apk_path, output_dir):
        cmd = f"java -jar {self.jar_path} d {apk_path} -o {output_dir} --force"
        return self.run(cmd)

    def recompile(self, source_dir, output_apk):
        cmd = f"java -jar {self.jar_path} b {source_dir} -o {output_apk}"
        return self.run(cmd)