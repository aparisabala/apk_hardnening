import subprocess

class APKTool:
    def __init__(self, jar_path):
        self.jar_path = jar_path

    def run(self, command):
        try:
            result = subprocess.run(
                command,
                shell=False,
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
        return self.run([
            "java", "-jar", self.jar_path,
            "d", apk_path, "-o", output_dir, "--force"
        ])

    def recompile(self, source_dir, output_apk):
        return self.run([
            "java", "-jar", self.jar_path,
            "b", source_dir, "-o", output_apk
        ])