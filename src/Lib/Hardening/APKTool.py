import subprocess
import sys
import os
import time
from pathlib import Path


class APKTool:

    def __init__(self, jar_path: str):
        self.jar_path = os.path.abspath(jar_path) if sys.platform.startswith("win") else jar_path
        if not os.path.isfile(self.jar_path):
            raise FileNotFoundError(f"apktool.jar not found at: {self.jar_path}")
        print(f"[APKTool] Initialized with jar: {self.jar_path}")

    def _run_with_timing(self, cmd_list: list, operation_name: str, timeout_sec: int = 1800) -> str:
        start_time = time.time()
        cmd_short = " ".join(cmd_list[:6]) + (" ..." if len(cmd_list) > 6 else "")
        env = os.environ.copy()
        if os.environ.get("SERVER_TYPE") == "SERVER":
            env["TMPDIR"] = "/home/pco/apk_tmp"
            env["TMP"] = "/home/pco/apk_tmp"
            env["TEMP"] = "/home/pco/apk_tmp"
            env["_JAVA_OPTIONS"] = "-Djava.io.tmpdir=/home/pco/apk_tmp"
        try:
            result = subprocess.run(
                cmd_list,
                shell=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout_sec,
                encoding="utf-8",
                errors="replace"
            )
            duration = time.time() - start_time
            output = (result.stdout or "").strip() + "\n" + (result.stderr or "").strip()
            if result.returncode != 0:
                msg = (
                    f"[APKTool {operation_name} ERROR] "
                    f"code={result.returncode} | time={duration:.2f}s\n"
                    f"Command: {cmd_short}\n"
                    f"Output:\n{output}"
                )
                print(msg)
                return msg
            success_msg = (
                f"[APKTool {operation_name} SUCCESS] "
                f"time taken = {duration:.2f} seconds\n"
                f"Command: {cmd_short}"
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
        
    def decompile(self, apk_path: str, output_dir: str, timeout_sec: int = 1800) -> str:

        apk_path = str(Path(apk_path).resolve())
        output_dir = str(Path(output_dir).resolve())
        os.makedirs(output_dir, exist_ok=True)
        cmd = [
            "java", "-jar", self.jar_path,
            "d", apk_path,
            "-o", output_dir,
            "--force"
        ]

        return self._run_with_timing(cmd, "DECOMPILE", timeout_sec)

    def recompile(self, source_dir: str, output_apk: str, timeout_sec: int = 1800) -> str:

        source_dir = str(Path(source_dir).resolve())
        output_apk = str(Path(output_apk).resolve())

        os.makedirs(os.path.dirname(output_apk), exist_ok=True)

        cmd = [
            "java", "-jar", self.jar_path,
            "b", source_dir,
            "-o", output_apk    
        ]
        return self._run_with_timing(cmd, "RECOMPILE", timeout_sec)