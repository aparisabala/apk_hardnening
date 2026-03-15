import subprocess
import sys
import os
import time
from pathlib import Path
import shutil

class APKTool:
    def __init__(self, jar_path: str, zipalign_path: str = None):
        self.jar_path = os.path.abspath(jar_path) if sys.platform.startswith("win") else jar_path
        if not os.path.isfile(self.jar_path):
            raise FileNotFoundError(f"apktool.jar not found at: {self.jar_path}")
        print(f"[APKTool] Initialized with jar: {self.jar_path}")

        # Full path to zipalign binary (optional)
        self.zipalign_path = zipalign_path or "zipalign"
        if not shutil.which(self.zipalign_path):
            print(f"[APKTool WARNING] zipalign not found in PATH: {self.zipalign_path}")

    def _get_env(self, job_id: str = "default_job") -> dict:
        env = os.environ.copy()
        if os.environ.get("SERVER_TYPE", "").upper() == "SERVER":
            tmp_path = f"/home/pco/apk_tmp/{job_id}"
            os.makedirs(tmp_path, exist_ok=True)
            env["TMPDIR"] = tmp_path
            env["TMP"] = tmp_path
            env["TEMP"] = tmp_path
            env["_JAVA_OPTIONS"] = f"-Djava.io.tmpdir={tmp_path}"
        return env

    def _run_with_timing(self, cmd_list: list, operation_name: str, job_id: str = "default_job", timeout_sec: int = 1800) -> str:
        start_time = time.time()
        cmd_short = " ".join(cmd_list[:6]) + (" ..." if len(cmd_list) > 6 else "")
        env = self._get_env(job_id)
        try:
            result = subprocess.run(
                cmd_list,
                shell=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout_sec,
                encoding="utf-8",
                errors="replace",
                env=env
            )
            duration = time.time() - start_time
            output = (result.stdout or "").strip() + "\n" + (result.stderr or "").strip()
            if result.returncode != 0:
                msg = (
                    f"[APKTool {operation_name} ERROR] code={result.returncode} | time={duration:.2f}s\n"
                    f"Command: {cmd_short}\nOutput:\n{output}"
                )
                print(msg)
                return msg
            success_msg = (
                f"[APKTool {operation_name} SUCCESS] time={duration:.2f}s | Command: {cmd_short}"
            )
            print(success_msg)
            return f"{success_msg}\n\n{output}"
        except subprocess.TimeoutExpired:
            msg = f"[APKTool {operation_name} TIMEOUT] after {timeout_sec}s | {cmd_short}"
            print(msg)
            return msg
        except Exception as e:
            duration = time.time() - start_time
            msg = f"[APKTool {operation_name} EXCEPTION] after {duration:.2f}s | {str(e)}"
            print(msg)
            return msg

    def decompile(self, apk_path: str, output_dir: str, job_id: str = "default_job", timeout_sec: int = 1800) -> str:
        apk_path = str(Path(apk_path).resolve())
        output_dir = str(Path(output_dir).resolve())
        os.makedirs(output_dir, exist_ok=True)
        cmd = ["java", "-jar", self.jar_path, "d", apk_path, "-o", output_dir, "--force"]
        return self._run_with_timing(cmd, "DECOMPILE", job_id, timeout_sec)

    def recompile(self, source_dir: str, output_apk: str, job_id: str = "default_job", timeout_sec: int = 1800) -> str:
        source_dir = str(Path(source_dir).resolve())
        output_apk = str(Path(output_apk).resolve())
        os.makedirs(os.path.dirname(output_apk), exist_ok=True)
        cmd = ["java", "-jar", self.jar_path, "b", source_dir, "-o", output_apk, "--force"]
        return self._run_with_timing(cmd, "RECOMPILE", job_id, timeout_sec)

    def zipalign_apk(self, input_apk: str, output_apk: str, job_id: str = "default_job") -> str:
        input_apk = str(Path(input_apk).resolve())
        output_apk = str(Path(output_apk).resolve())
        os.makedirs(os.path.dirname(output_apk), exist_ok=True)

        if not shutil.which(self.zipalign_path):
            return f"[ZIPALIGN ERROR] zipalign not found: {self.zipalign_path}"

        cmd = [self.zipalign_path, "-v", "4", input_apk, output_apk]
        return self._run_with_timing(cmd, "ZIPALIGN", job_id)