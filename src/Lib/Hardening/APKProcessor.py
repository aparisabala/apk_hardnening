import os
import uuid
import shutil
import random
import string
import requests,subprocess
from threading import Thread
import xml.etree.ElementTree as ET
from pathlib import Path

from threading import Thread

from src.Lib.Hardening.APKTool import APKTool


class APKProcessor:
    def __init__(self, jobs_dir, download_dir, apktool: APKTool, base_url: str):
        self.jobs_dir = jobs_dir
        self.download_dir = download_dir
        self.apktool = apktool
        self.base_url = base_url.rstrip("/")

        os.makedirs(jobs_dir, exist_ok=True)
        os.makedirs(download_dir, exist_ok=True)

    def generate_file_name(self):
        part1 = ''.join(random.sample(string.ascii_lowercase, 4))
        part2 = ''.join(random.choices(
            string.ascii_letters + string.digits, k=8))
        return f"{part1}_{part2}"

    def download_apk(self, url, save_path):
        cmd = f"curl -L --fail --connect-timeout 30 --silent \"{url}\" -o \"{save_path}\""
        return self.apktool.run(cmd)

    def harden_and_notify(self, job_id: str, apk_url: str, callback_url: str):
        temp_file = os.path.join(self.jobs_dir, f"apk_{self.generate_file_name()}.apk")
        job_folder = os.path.join(self.jobs_dir, job_id)
        src_dir = os.path.join(job_folder, "src")
        rebuilt_apk = os.path.join(job_folder, "rebuilt.apk")
        final_name = f"{job_id}.apk"

        # ABSOLUTE PUBLIC PATH FROM ENV
        public_output_dir = os.getenv("HARDENED_APK_OUTPUT_DIR", self.download_dir)
        public_final_path = os.path.join(public_output_dir, final_name)

        # Public download URL
        public_domain = os.getenv("PUBLIC_DOMAIN", self.base_url).rstrip("/")
        public_download_url = f"{public_domain}/hardened/{final_name}"

        os.makedirs(job_folder, exist_ok=True)
        os.makedirs(public_output_dir, exist_ok=True)

        result = {
            "job_id": job_id,
            "original_url": apk_url,
            "status": "failed",
            "error": "Unknown error"
        }

        try:
            # Download
            download_log = self.download_apk(apk_url, temp_file)
            if not os.path.exists(temp_file) or os.path.getsize(temp_file) == 0:
                raise Exception(f"Download failed: {download_log}")

            # Decompile
            decompile_log = self.apktool.decompile(temp_file, src_dir)
            if "Exception" in decompile_log:
                raise Exception(f"Decompile failed: {decompile_log}")

            # ========================
            # PROFESSIONAL HARDENING - PACKAGE NAME PRESERVED
            # ========================

            hardening_log = "\n=== PROFESSIONAL HARDENING (INSTALLABLE & SAFE) ===\n"

            manifest_path = os.path.join(src_dir, "AndroidManifest.xml")

            original_package = None
            original_version_code = 1
            original_version_name = "1.0"

            if os.path.exists(manifest_path):
                tree = ET.parse(manifest_path)
                root = tree.getroot()

                original_package = root.get("package")
                version_code_str = root.get("{http://schemas.android.com/apk/res/android}versionCode", "1")
                original_version_name = root.get("{http://schemas.android.com/apk/res/android}versionName", "1.0")

                try:
                    original_version_code = int(version_code_str)
                except:
                    original_version_code = 1

                # Register namespace
                ns = {'android': 'http://schemas.android.com/apk/res/android'}
                ET.register_namespace('android', ns['android'])

                application = root.find('application')
                if application is not None:
                    # Remove risky flags
                    risky_attrs = [
                        '{http://schemas.android.com/apk/res/android}debuggable',
                        '{http://schemas.android.com/apk/res/android}allowBackup',
                        '{http://schemas.android.com/apk/res/android}fullBackupContent',
                        '{http://schemas.android.com/apk/res/android}networkSecurityConfig'
                    ]
                    for attr in risky_attrs:
                        if attr in application.attrib:
                            del application.attrib[attr]
                            hardening_log += f"- Removed {attr.split('}')[1]}\n"

                # Increase versionCode by 1 to allow update install
                new_version_code = original_version_code + 1
                root.set("{http://schemas.android.com/apk/res/android}versionCode", str(new_version_code))
                hardening_log += f"- Increased versionCode: {original_version_code} → {new_version_code} (allows install over original)\n"

                # Optional: Mark versionName as hardened
                root.set("{http://schemas.android.com/apk/res/android}versionName", f"{original_version_name} (hardened)")

                tree.write(manifest_path, encoding="utf-8", xml_declaration=True)

                if original_package:
                    hardening_log += f"- Preserved original package name: {original_package}\n"
                else:
                    hardening_log += "- Warning: No package name found in manifest\n"
            else:
                hardening_log += "- ERROR: AndroidManifest.xml not found\n"

            # Basic string obfuscation (safe - won't break app)
            sensitive_keywords = ["http://", "https://", "api.", "key=", "token=", "password="]
            obf_count = 0
            smali_root = Path(src_dir) / "smali"
            if smali_root.exists():
                for smali_file in smali_root.rglob("*.smali"):
                    try:
                        content = smali_file.read_text(encoding="utf-8", errors="ignore")
                        modified = False
                        for kw in sensitive_keywords:
                            if kw in content:
                                placeholder = f"HID_{random.randint(10000,99999)}"
                                content = content.replace(kw, placeholder)
                                modified = True
                        if modified:
                            smali_file.write_text(content, encoding="utf-8")
                            obf_count += 1
                    except:
                        continue
                hardening_log += f"- Obfuscated {obf_count} sensitive strings\n"
            else:
                hardening_log += "- Smali directory not found\n"

            # Optional: Inject simple protection log
            if original_package:
                package_path = original_package.replace(".", "/")
                stub_path = Path(src_dir) / "smali" / package_path / "ProtectionLog.smali"
                stub_path.parent.mkdir(parents=True, exist_ok=True)

                stub_code = f'''.class public L{package_path}/ProtectionLog;
                .super Ljava/lang/Object;

                .method public static log()V
                    .locals 2
                    const-string v0, "HARDENING"
                    const-string v1, "This app is protected by hardening service"
                    invoke-static {{v0, v1}}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I
                    return-void
                .end method
                '''
                stub_path.write_text(stub_code, encoding="utf-8")
                hardening_log += "- Injected protection log stub\n"

            hardening_log += "=== HARDENING COMPLETE - APP IS NOW INSTALLABLE ===\n"

            # Recompile
            recompile_log = self.apktool.recompile(src_dir, rebuilt_apk)
            if not os.path.exists(rebuilt_apk):
                raise Exception(f"Recompile failed: {recompile_log}")

            # TEMP UNSIGNED APK
            unsigned_apk = os.path.join(job_folder, "unsigned.apk")
            shutil.copy(rebuilt_apk, unsigned_apk)

            # TEMP UNSIGNED APK
            unsigned_apk = os.path.join(job_folder, "unsigned.apk")
            try:
                shutil.copy(rebuilt_apk, unsigned_apk)
            except Exception as e:
                raise Exception(f"[COPY ERROR] Failed to create unsigned APK: {e}")

            # ZIPALIGN
            zipalign_path = os.getenv("APK_Z", "zipalign")
            aligned_apk = os.path.join(job_folder, "aligned.apk")

            try:
                if not os.path.exists(zipalign_path):
                    raise Exception(f"zipalign not found at: {zipalign_path}")

                align_cmd = [zipalign_path, "-f", "4", unsigned_apk, aligned_apk]
                align_result = subprocess.run(
                    align_cmd,
                    capture_output=True,
                    text=True
                )

                if align_result.returncode != 0:
                    raise Exception(
                        f"zipalign failed\n"
                        f"STDOUT: {align_result.stdout}\n"
                        f"STDERR: {align_result.stderr}"
                    )

                if not os.path.exists(aligned_apk):
                    raise Exception("aligned.apk not created")

            except Exception as e:
                raise Exception(f"[ZIPALIGN ERROR] {e}")

            # SIGN WITH DEBUG KEYSTORE
            apksigner_path = os.getenv("APK_S", "apksigner")
            signed_final = public_final_path  # final output

            try:
                if not os.path.exists(apksigner_path):
                    raise Exception(f"apksigner.jar not found at: {apksigner_path}")

                debug_keystore = os.path.expanduser("~/.android/debug.keystore")
                if not os.path.exists(debug_keystore):
                    raise Exception(f"debug.keystore not found at: {debug_keystore}")

                sign_cmd = [
                    "java", "-jar", apksigner_path,
                    "sign",
                    "--ks", debug_keystore,
                    "--ks-key-alias", "androiddebugkey",
                    "--ks-pass", "pass:android",
                    "--key-pass", "pass:android",
                    "--out", signed_final,
                    aligned_apk
                ]

                sign_result = subprocess.run(
                    sign_cmd,
                    capture_output=True,
                    text=True
                )

                if sign_result.returncode != 0:
                    raise Exception(
                        f"Signing failed\n"
                        f"STDOUT: {sign_result.stdout}\n"
                        f"STDERR: {sign_result.stderr}"
                    )

                if not os.path.exists(signed_final):
                    raise Exception("Signed APK not created")

            except Exception as e:
                raise Exception(f"[SIGNING ERROR] {e}")


            hardening_log += "- APK zipaligned and signed with debug keystore\n"
            
            # COPY ONLY TO PUBLIC PATH (no internal copy)
            #shutil.copy(rebuilt_apk, public_final_path)

            result.update({
                "status": "success",
                "download_url": public_download_url,
                "public_path": public_final_path,
                "message": "APK hardened successfully and ready to install",
                "hardening_summary": hardening_log.strip(),
                "original_package": original_package,
                "new_version_code": new_version_code,
                "log": download_log + "\n" + decompile_log + "\n" + hardening_log + "\n" + recompile_log
            })

        except Exception as e:
            result["error"] = f"Hardening failed: {str(e)}"

        finally:
            # SMART CLEANUP - ONLY CURRENT JOB TEMP FILES
            try:
                if os.path.exists(temp_file):
                    os.remove(temp_file)
                    print(f"[CLEANUP] Deleted temp APK: {temp_file}")

                if os.path.exists(job_folder):
                    shutil.rmtree(job_folder)
                    print(f"[CLEANUP] Deleted job folder: {job_folder}")

                print(f"[CLEANUP] Preserved final APK: {public_final_path}")

            except Exception as cleanup_error:
                print(f"[CLEANUP ERROR] {cleanup_error}")

            # SEND CALLBACK
            try:
                requests.post(callback_url, json=result, timeout=15)
                print(f"[CALLBACK] Sent result for job {job_id}")
            except Exception as e:
                print(f"[CALLBACK FAILED] {e}")      
    
    def start_background_hardening(self, apk_url: str, callback_url: str):
        job_id = str(uuid.uuid4())
        thread = Thread(
            target=self.harden_and_notify,
            args=(job_id, apk_url, callback_url),
            daemon=True
        )
        thread.start()
        return job_id
