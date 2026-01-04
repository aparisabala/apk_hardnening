import subprocess
import sys
import os

class APKTool:
    def __init__(self, jar_path):
        # Detect OS and normalize path
        if sys.platform.startswith("win"):
            # Ensure Windows paths use backslashes
            self.jar_path = os.path.abspath(jar_path)
        else:
            # Linux paths, keep as-is
            self.jar_path = jar_path

    def run(self, command):
        try:
            result = subprocess.run(
                command,
                shell=False,       # never True; keeps cross-platform safe
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=3600
            )
            output = result.stdout + result.stderr
            if result.returncode != 0:
                return f"ERROR (code {result.returncode}): {output}"
            return output
        except subprocess.TimeoutExpired:
            return "ERROR: Command timed out"
        except Exception as e:
            return f"EXCEPTION: {str(e)}"

    def decompile(self, apk_path, output_dir):
        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)

        # Run apktool via java -jar (works on Windows + Linux)
        return self.run([
            "java", "-jar", self.jar_path,
            "d", apk_path, "-o", output_dir, "--force"
        ])

    def recompile(self, source_dir, output_apk):
        # Ensure parent directory exists
        os.makedirs(os.path.dirname(output_apk), exist_ok=True)

        # Run apktool via java -jar (works on Windows + Linux)
        return self.run([
            "java", "-jar", self.jar_path,
            "b", source_dir, "-o", output_apk
        ])
