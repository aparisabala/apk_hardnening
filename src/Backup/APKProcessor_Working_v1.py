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
from typing import Optional

from src.Lib.Hardening.Job import Job
from src.Lib.Hardening.APKTool import APKTool


class APKProcessor:
    """
    Clean APK Hardening Processor
    - Preserves all API URLs (http/https/api.) completely intact
    - Supports polymorphic package renaming (random or custom)
    - Persistent keystore per final package name (reused for updates)
    - Injects custom versionCode if provided
    - Always sends callback with 'id' included
    - No unfinished APKs are ever exposed
    """

    def __init__(self, jobs_dir: str, download_dir: str, apktool: APKTool, base_url: str):
        self.jobs_dir = Path(jobs_dir)
        self.download_dir = Path(download_dir)
        self.apktool = apktool
        self.base_url = base_url.rstrip("/")

        self.jobs_dir.mkdir(parents=True, exist_ok=True)
        self.download_dir.mkdir(parents=True, exist_ok=True)

    def _keystore_for_package(self, package: str) -> Path:
        """Persistent keystore tied to final package name — never deleted."""
        keystore_dir = self.jobs_dir / "keystores"
        keystore_dir.mkdir(parents=True, exist_ok=True)

        safe_name = hashlib.sha256(package.encode()).hexdigest()[:16]
        keystore_path = keystore_dir / f"{safe_name}.keystore"

        if not keystore_path.exists():
            cmd = [
                "keytool", "-genkeypair", "-v",
                "-keystore", str(keystore_path),
                "-storepass", "android",
                "-keypass", "android",
                "-alias", "androiddebugkey",
                "-keyalg", "RSA",
                "-keysize", "2048",
                "-validity", "10000",
                "-dname", "CN=Hardening,O=APK,L=Local,C=US"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                raise Exception(f"Keystore generation failed: {result.stderr}")

        return keystore_path

    def _generate_random_package(self) -> str:
        """Generates a random package name like com.abc.x7k9p2m4q1"""
        return f"com.{''.join(random.choices(string.ascii_lowercase, k=3))}.{''.join(random.choices(string.ascii_lowercase + string.digits, k=10))}"

    def _download_apk(self, url: str, save_path: Path):
        cmd = ["curl", "-L", "--fail", "--connect-timeout", "30", "--silent", url, "-o", str(save_path)]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise Exception(f"Download failed: {result.stderr}")

    def _parse_manifest(self, manifest_path: Path):
        if not manifest_path.exists():
            return None, 1, "1.0", None, None

        tree = ET.parse(manifest_path)
        root = tree.getroot()
        package = root.get("package")
        version_code_str = root.get("{http://schemas.android.com/apk/res/android}versionCode", "1")
        version_name = root.get("{http://schemas.android.com/apk/res/android}versionName", "1.0")
        version_code = int(version_code_str) if version_code_str.isdigit() else 1
        return package, version_code, version_name, tree, root

    def _rename_package(self, src_dir: Path, old_package: str, new_package: str):
        """Updates package directories and all references in smali files."""
        old_path = old_package.replace('.', '/')
        new_path = new_package.replace('.', '/')

        smali_dirs = [d for d in src_dir.iterdir() if d.is_dir() and d.name.startswith('smali')]

        for smali_dir in smali_dirs:
            old_dir = smali_dir / old_path
            if old_dir.exists():
                new_dir = smali_dir / new_path
                new_dir.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(old_dir), str(new_dir))

            for smali_file in smali_dir.rglob("*.smali"):
                try:
                    content = smali_file.read_text(encoding="utf-8", errors="ignore")
                    if f"L{old_path}/" in content:
                        content = content.replace(f"L{old_path}/", f"L{new_path}/")
                        smali_file.write_text(content, encoding="utf-8")
                except:
                    continue

        # Replace hard-coded package strings (e.g., const-string "com.old.app")
        for smali_file in src_dir.rglob("*.smali"):
            try:
                content = smali_file.read_text(encoding="utf-8", errors="ignore")
                if old_package in content:
                    content = content.replace(old_package, new_package)
                    smali_file.write_text(content, encoding="utf-8")
            except:
                continue

    def _harden_manifest(self, job: Job, root, tree, manifest_path: Path, original_version_code: int, original_version_name: str) -> int:
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

        new_version_code = job.current_version if job.current_version is not None else original_version_code + 1
        root.set("{http://schemas.android.com/apk/res/android}versionCode", str(new_version_code))
        root.set("{http://schemas.android.com/apk/res/android}versionName", f"{original_version_name} (hardened)")

        tree.write(manifest_path, encoding="utf-8", xml_declaration=True)
        return new_version_code

    def _inject_protection_stub(self, src_dir: Path, package: str):
        """Injects a harmless log stub to indicate hardening."""
        package_path = package.replace(".", "/")
        stub_path = src_dir / "smali" / package_path / "ProtectionLog.smali"
        stub_path.parent.mkdir(parents=True, exist_ok=True)

        stub_content = f'''.class public L{package_path}/ProtectionLog;
.super Ljava/lang/Object;

.method public static log()V
    .locals 2
    const-string v0, "HARDENING"
    const-string v1, "This app is protected by hardening service"
    invoke-static {{v0, v1}}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I
    return-void
.end method'''
        stub_path.write_text(stub_content, encoding="utf-8")

    def _zipalign_apk(self, unsigned_apk: Path, aligned_apk: Path):
        zipalign_path = os.getenv("APK_Z", "zipalign")
        result = subprocess.run([zipalign_path, "-f", "4", str(unsigned_apk), str(aligned_apk)], capture_output=True, text=True)
        if result.returncode != 0 or not aligned_apk.exists():
            raise Exception(f"zipalign failed: {result.stderr}")

    def _sign_apk(self, aligned_apk: Path, signed_apk: Path, keystore: Path):
        base_cmd = ["java", "-jar", os.getenv("APK_S", "apksigner")] if os.getenv('SERVER_TYPE') == "LOCAL" else [os.getenv("APK_S", "apksigner")]
        cmd = base_cmd + [
            "sign",
            "--ks", str(keystore),
            "--ks-key-alias", "androiddebugkey",
            "--ks-pass", "pass:android",
            "--key-pass", "pass:android",
            "--out", str(signed_apk),
            str(aligned_apk)
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise Exception(f"Signing failed: {result.stderr}")

    def harden_and_notify(self, job: Job):
        temp_file = self.jobs_dir / f"{job.file_name}.apk"
        job_folder = self.jobs_dir / job.job_id
        src_dir = job_folder / "src"
        rebuilt_apk = job_folder / "rebuilt.apk"
        unsigned_apk = job_folder / "unsigned.apk"
        aligned_apk = job_folder / "aligned.apk"

        public_output_dir = Path(os.getenv("HARDENED_APK_OUTPUT_DIR", self.download_dir))
        public_output_dir.mkdir(parents=True, exist_ok=True)
        signed_final = public_output_dir / f"uploads/{job.domain}/app/apk/{job.file_name}.apk"
        public_download_url = f"{os.getenv('PUBLIC_DOMAIN', self.base_url).rstrip('/')}/hardened/{job.job_id}.apk"

        result = {
            "job_id": job.job_id,
            "original_url": job.apk_url,
            "status": "failed",
            "error": "Unknown error",
            "id": job.id
        }

        try:
            # 1. Download
            self._download_apk(job.apk_url, temp_file)
            if not temp_file.exists() or temp_file.stat().st_size == 0:
                raise Exception("Downloaded APK is empty")

            # 2. Decompile
            decompile_log = self.apktool.decompile(str(temp_file), str(src_dir))
            if "ERROR" in decompile_log or "Exception" in decompile_log:
                raise Exception(decompile_log)

            # 3. Parse manifest
            manifest_path = src_dir / "AndroidManifest.xml"
            current_package, orig_vcode, orig_vname, tree, root = self._parse_manifest(manifest_path)

            # 4. Determine target package
            target_package = current_package
            if job.package_name_method == "random":
                target_package = self._generate_random_package()
            elif job.package_name_method == "no_random" and job.package_name and job.package_name != current_package:
                target_package = job.package_name

            # 5. Rename package if needed
            if target_package != current_package:
                root.set("package", target_package)
                tree.write(manifest_path, encoding="utf-8", xml_declaration=True)
                self._rename_package(src_dir, current_package, target_package)

            # 6. Harden manifest (version + remove risky attrs)
            new_version_code = self._harden_manifest(job, root, tree, manifest_path, orig_vcode, orig_vname)

            # 7. Inject protection stub
            self._inject_protection_stub(src_dir, target_package)

            # 8. Recompile
            recompile_log = self.apktool.recompile(str(src_dir), str(rebuilt_apk))
            if not rebuilt_apk.exists():
                raise Exception(recompile_log)

            # 9. Sign with persistent keystore
            keystore = self._keystore_for_package(target_package)
            shutil.copy(rebuilt_apk, unsigned_apk)
            self._zipalign_apk(unsigned_apk, aligned_apk)
            self._sign_apk(aligned_apk, signed_final, keystore)

            # Success response
            result.update({
                "status": "success",
                "download_url": public_download_url,
                "public_path": str(signed_final),
                "file_name": f"{job.file_name}.apk",
                "message": "APK hardened successfully",
                "hardening_summary": "Package renamed (if requested), version updated, protection stub injected — ALL API URLs PRESERVED",
                "original_package": current_package,
                "new_package": target_package,
                "new_version_code": new_version_code,
                "id": job.id
            })

        except Exception as e:
            result["error"] = str(e)
            result["id"] = job.id

        finally:
            # Clean only temporary files — keystore remains forever
            for p in [temp_file, job_folder]:
                if p and p.exists():
                    if p.is_dir():
                        shutil.rmtree(p, ignore_errors=True)
                    else:
                        p.unlink(missing_ok=True)

            # Always send callback
            try:
                requests.post(job.callback_url, json=result, timeout=15)
                print(f"[JOB {job.job_id}] Callback sent")
            except Exception as cb_e:
                print(f"[JOB {job.job_id}] Callback failed: {cb_e}")

    def start_background_hardening(self, job: Job) -> str:
        Thread(target=self.harden_and_notify, args=(job,), daemon=True).start()
        return job.job_id