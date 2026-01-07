import os
import uuid
import shutil
import random
import string
import requests
import subprocess
from threading import Thread
from pathlib import Path
import xml.etree.ElementTree as ET
import hashlib
from src.Lib.Hardening.APKTool import APKTool
from src.Lib.Socket.emitter import emit
class APKProcessor:
    
    def __init__(self, jobs_dir: str, download_dir: str, apktool: APKTool, base_url: str):
        self.jobs_dir = Path(jobs_dir)
        self.download_dir = Path(download_dir)
        self.apktool = apktool
        self.base_url = base_url.rstrip("/")

        self.jobs_dir.mkdir(parents=True, exist_ok=True)
        self.download_dir.mkdir(parents=True, exist_ok=True)
        
    def _keystore_for_job(self, job_id: str) -> Path:
        keystore_dir = Path(self.jobs_dir) / "keystores"
        keystore_dir.mkdir(parents=True, exist_ok=True)

        safe_name = hashlib.sha256(job_id.encode()).hexdigest()[:16]
        keystore_path = keystore_dir / f"{safe_name}.keystore"

        if not keystore_path.exists():
            cmd = [
                "keytool",
                "-genkeypair",
                "-v",
                "-keystore", str(keystore_path),
                "-storepass", "android",
                "-keypass", "android",
                "-alias", "androiddebugkey",
                "-keyalg", "RSA",
                "-keysize", "2048",
                "-validity", "10000",
                "-dname", "CN=Hardening,O=APK,L=Local,C=US"
            ]
            result =  subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                raise Exception(f"Failed to generate keystore\nSTDOUT:{result.stdout}\nSTDERR:{result.stderr}")
            return keystore_path

    def generate_file_name(self) -> str:
        part1 = ''.join(random.sample(string.ascii_lowercase, 4))
        part2 = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
        return f"{part1}_{part2}"

    def download_apk(self, url: str, save_path: str) -> str:
        cmd = [
            "curl",
            "-L",
            "--fail",
            "--connect-timeout", "30",
            "--silent",
            url,
            "-o",
            save_path
        ]

        try:
            result = self.apktool.run(cmd)  # Make sure apktool.run handles list input
            return result
        except FileNotFoundError:
            raise Exception("Curl is not installed or not in PATH")
        except Exception as e:
            raise Exception(f"APK download failed: {e}")


    def _parse_manifest(self, manifest_path: Path):
        package = None
        version_code = 1
        version_name = "1.0"

        if not manifest_path.exists():
            return package, version_code, version_name

        tree = ET.parse(manifest_path)
        root = tree.getroot()
        package = root.get("package")

        version_code_str = root.get("{http://schemas.android.com/apk/res/android}versionCode", "1")
        version_name = root.get("{http://schemas.android.com/apk/res/android}versionName", "1.0")

        try:
            version_code = int(version_code_str)
        except:
            version_code = 1

        return package, version_code, version_name, tree, root

    def _harden_manifest(self, root, tree, manifest_path: Path):
        ET.register_namespace('android', 'http://schemas.android.com/apk/res/android')

        application = root.find('application')
        if application:
            for attr in [
                '{http://schemas.android.com/apk/res/android}debuggable',
                '{http://schemas.android.com/apk/res/android}allowBackup',
                '{http://schemas.android.com/apk/res/android}fullBackupContent',
                '{http://schemas.android.com/apk/res/android}networkSecurityConfig'
            ]:
                application.attrib.pop(attr, None)

        original_version_code = int(root.get("{http://schemas.android.com/apk/res/android}versionCode", "1"))
        new_version_code = original_version_code + 1
        root.set("{http://schemas.android.com/apk/res/android}versionCode", str(new_version_code))
        version_name = root.get("{http://schemas.android.com/apk/res/android}versionName", "1.0")
        root.set("{http://schemas.android.com/apk/res/android}versionName", f"{version_name} (hardened)")

        tree.write(manifest_path, encoding="utf-8", xml_declaration=True)
        return new_version_code

    def _obfuscate_smali(self, smali_root: Path):
        keywords = ["http://", "https://", "api.", "key=", "token=", "password="]
        count = 0
        if not smali_root.exists():
            return count

        for smali_file in smali_root.rglob("*.smali"):
            try:
                content = smali_file.read_text(encoding="utf-8", errors="ignore")
                modified = False
                for kw in keywords:
                    if kw in content:
                        content = content.replace(kw, f"HID_{random.randint(10000, 99999)}")
                        modified = True
                if modified:
                    smali_file.write_text(content, encoding="utf-8")
                    count += 1
            except:
                continue
        return count

    def _inject_protection_stub(self, src_dir: Path, package: str):
        
        package_path = package.replace(".", "/")
        stub_path = src_dir / "smali" / package_path / "ProtectionLog.smali"
        stub_path.parent.mkdir(parents=True, exist_ok=True)
        stub_path.write_text(f'''.class public L{package_path}/ProtectionLog;
        .super Ljava/lang/Object;

        .method public static log()V
            .locals 2
            const-string v0, "HARDENING"
            const-string v1, "This app is protected by hardening service"
            invoke-static {{v0, v1}}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I
            return-void
        .end method
        ''', encoding="utf-8")

    def _zipalign_apk(self, unsigned_apk: Path, aligned_apk: Path):
        
        zipalign_path = os.getenv("APK_Z", "zipalign")
        if Path(zipalign_path).is_absolute() and not Path(zipalign_path).exists():
            raise Exception(f"zipalign not found at {zipalign_path}")

        result = subprocess.run([zipalign_path, "-f", "4", str(unsigned_apk), str(aligned_apk)],capture_output=True, text=True)
        if result.returncode != 0 or not aligned_apk.exists():
            raise Exception(f"zipalign failed\nSTDOUT:{result.stdout}\nSTDERR:{result.stderr}")

    def _sign_apk(self, aligned_apk: Path, signed_apk: Path, keystore: Path):
        sign_cmd = []
        if os.getenv('SERVER_TYPE') == "LOCAL":
            sign_cmd.extend(["java", "-jar", str(os.getenv("APK_S", "apksigner"))])
        else:
            sign_cmd.append(str(os.getenv("APK_S", "apksigner")))
        sign_cmd += [
            "sign",
            "--ks", str(keystore),
            "--ks-key-alias", "androiddebugkey",
            "--ks-pass", "pass:android",
            "--key-pass", "pass:android",
            "--out", str(signed_apk),
            str(aligned_apk)
        ]
        result = subprocess.run(sign_cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise Exception(f"Signing failed\nSTDOUT:{result.stdout}\nSTDERR:{result.stderr}")

    def harden_and_notify(self, job_id: str, apk_url: str, callback_url: str, id: int, domain: string, file_name: string):
        temp_file = self.jobs_dir / f"{file_name}.apk"
        job_folder = self.jobs_dir / job_id
        src_dir = job_folder / "src"
        rebuilt_apk = job_folder / "rebuilt.apk"
        unsigned_apk = job_folder / "unsigned.apk"
        aligned_apk = job_folder / "aligned.apk"

        public_output_dir = Path(os.getenv("HARDENED_APK_OUTPUT_DIR", self.download_dir))
        public_output_dir.mkdir(parents=True, exist_ok=True)
        signed_final = public_output_dir / f"uploads/{domain}/app/apk/{file_name}.apk"
        public_download_url = f"{os.getenv('PUBLIC_DOMAIN', self.base_url).rstrip('/')}/hardened/{job_id}.apk"

        result = {"job_id": job_id, "original_url": apk_url, "status": "failed", "error": "Unknown error"}

        try:
            download_log = self.download_apk(apk_url, temp_file)
            if not temp_file.exists() or temp_file.stat().st_size == 0:
                raise Exception(download_log)

            decompile_log = self.apktool.decompile(temp_file, src_dir)
            if "Exception" in decompile_log:
                raise Exception(decompile_log)

            manifest_path = src_dir / "AndroidManifest.xml"
            package, version_code, version_name, tree, root = self._parse_manifest(manifest_path)

            new_version_code = self._harden_manifest(root, tree, manifest_path) if root else 1
            obf_count = self._obfuscate_smali(src_dir / "smali")

            if package:
                self._inject_protection_stub(src_dir, package)

            recompile_log = self.apktool.recompile(src_dir, rebuilt_apk)
            if not rebuilt_apk.exists():
                raise Exception(recompile_log)
            
            keystore = self._keystore_for_job(job_id)
            if not keystore.exists():
                raise Exception(f"debug.keystore not found at {keystore}")

            shutil.copy(rebuilt_apk, unsigned_apk)
            self._zipalign_apk(unsigned_apk, aligned_apk)
            self._sign_apk(aligned_apk, signed_final, keystore)

            result.update({
                "status": "success",
                "download_url": public_download_url,
                "public_path": str(signed_final),
                "id": id,
                "file_name": f"{file_name}.apk",
                "message": "APK hardened successfully and ready to install",
                "hardening_summary": f"Obfuscated {obf_count} strings, versionCode updated, protection stub injected",
                "original_package": package,
                "new_version_code": new_version_code,
                "log": "\n".join([download_log, decompile_log, recompile_log])
            })

        except Exception as e:
            result["error"] = str(e)

        finally:
            try:
                if os.path.exists(temp_file):
                    os.remove(temp_file)
                if os.path.exists(job_folder):
                    shutil.rmtree(job_folder)
                if keystore.exists():
                    keystore.unlink()
            except:
                pass
            print(f"[JOB {job_id}] Finished with status: success, sending callback")
            try:
                requests.post(callback_url, json=result, timeout=15)
                print(f"[JOB {job_id}] Callback sent successfully to {callback_url}")
            except Exception as e:
                print(f"[JOB {job_id}] Callback failed: {e}")

    def start_background_hardening(self, apk_url: str, callback_url: str, id: int, domain: string, file_name: string) -> str:
        job_id = str(uuid.uuid4())
        Thread(target=self.harden_and_notify, args=(job_id, apk_url, callback_url,id, domain,file_name), daemon=True).start()
        return job_id
