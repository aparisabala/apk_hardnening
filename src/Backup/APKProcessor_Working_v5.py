import os
import sys
import uuid
import shutil
import random
import string
import requests
import subprocess
import base64
from threading import Thread
from pathlib import Path
import xml.etree.ElementTree as ET
from typing import Optional, Tuple

from src.Lib.Hardening.Job import Job
from src.Lib.Hardening.APKTool import APKTool


class APKProcessor:

    def __init__(self, jobs_dir: str, download_dir: str, apktool: APKTool, base_url: str):
        self.jobs_dir = Path(jobs_dir)
        self.download_dir = Path(download_dir)
        self.apktool = apktool
        self.base_url = base_url.rstrip("/")

        self.jobs_dir.mkdir(parents=True, exist_ok=True)
        self.download_dir.mkdir(parents=True, exist_ok=True)

    def _keystore_for_package(self, job: Job) -> Path:

        keystore_dir = self.jobs_dir / "keystores"
        keystore_dir.mkdir(parents=True, exist_ok=True)

        keystore_path = keystore_dir / f"{job.file_name}_{job.id}.keystore"

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

        ET.register_namespace('android', 'http://schemas.android.com/apk/res/android')

        package = root.get("package")
        version_code_str = root.get("{http://schemas.android.com/apk/res/android}versionCode", "1")
        version_name = root.get("{http://schemas.android.com/apk/res/android}versionName", "1.0")
        version_code = int(version_code_str) if version_code_str.isdigit() else 1

        return package, version_code, version_name, tree, root

    def _rename_package(self, src_dir: Path, old_package: str, new_package: str):
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

    def _get_launcher_components(self, root):
        ns = {'android': 'http://schemas.android.com/apk/res/android'}
        launchers = []
        for elem in root.findall(".//activity") + root.findall(".//activity-alias"):
            for intent in elem.findall(".//intent-filter"):
                action = intent.find("action[@android:name='android.intent.action.MAIN']", ns)
                category = intent.find("category[@android:name='android.intent.category.LAUNCHER']", ns)
                if action is not None and category is not None:
                    launchers.append(elem)
        return launchers

    def _get_current_display_name(self, root, src_dir: Path) -> str:
        launchers = self._get_launcher_components(root)
        if launchers:
            label = launchers[0].get("{http://schemas.android.com/apk/res/android}label")
            if label:
                if label.startswith("@string/"):
                    res_name = label.split("/")[-1]
                    strings_path = src_dir / "res" / "values" / "strings.xml"
                    if strings_path.exists():
                        try:
                            tree = ET.parse(strings_path)
                            elem = tree.find(f".//string[@name='{res_name}']")
                            if elem is not None and elem.text:
                                return elem.text
                        except:
                            pass
                return label

        application = root.find("application")
        if application is not None:
            label = application.get("{http://schemas.android.com/apk/res/android}label")
            if label:
                if label.startswith("@string/"):
                    res_name = label.split("/")[-1]
                    strings_path = src_dir / "res" / "values" / "strings.xml"
                    if strings_path.exists():
                        try:
                            tree = ET.parse(strings_path)
                            elem = tree.find(f".//string[@name='{res_name}']")
                            if elem is not None and elem.text:
                                return elem.text
                        except:
                            pass
                return label
        return "Unknown App"
    
    def _cleanup_manifest_permissions(self, root):
        ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
        critical_permissions = {
            "android.permission.READ_PRIVILEGED_PHONE_STATE",
            "android.permission.MOUNT_UNMOUNT_FILESYSTEMS",
            "android.permission.MODIFY_PHONE_STATE",
            "android.permission.PACKAGE_USAGE_STATS",
            "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
            "android.permission.REQUEST_INSTALL_PACKAGES",          
            "android.permission.SYSTEM_ALERT_WINDOW",                
            "android.permission.WRITE_SETTINGS",                    
            "android.permission.READ_LOGS",                         
        }
        dangerous_permissions = {
            "android.permission.READ_SMS",
            "android.permission.SEND_SMS",
            "android.permission.READ_CONTACTS",
            "android.permission.WRITE_CONTACTS",
            "android.permission.READ_CALL_LOG",
            "android.permission.PROCESS_OUTGOING_CALLS",
            "android.permission.CALL_PHONE",
            "android.permission.ANSWER_PHONE_CALLS",
            "android.permission.READ_PHONE_STATE",                    
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.ACCESS_BACKGROUND_LOCATION",
            "android.permission.RECORD_AUDIO",
            "android.permission.CAMERA",
            "android.permission.READ_EXTERNAL_STORAGE",               
            "android.permission.WRITE_EXTERNAL_STORAGE",             
        }
        permissions_to_remove = critical_permissions | dangerous_permissions
        removed_count = 0
        permissions_found = set()
        for perm in list(root.findall("uses-permission")) + list(root.findall("uses-permission-sdk-23")):
            name = perm.get(f"{ANDROID_NS}name")
            if name:
                permissions_found.add(name)
                if name in permissions_to_remove or name.lower() in permissions_to_remove:
                    root.remove(perm)
                    removed_count += 1
        if removed_count > 0:
            print(f"[Hardening] Removed {removed_count} risky permissions")
        return removed_count
    
    def _update_string_resource(self, src_dir: Path, res_name: str, new_value: str) -> bool:
        strings_path = src_dir / "res" / "values" / "strings.xml"
        if not strings_path.exists():
            return False

        try:
            tree = ET.parse(strings_path)
            updated = False
            for elem in tree.findall(f".//string[@name='{res_name}']"):
                elem.text = new_value
                updated = True
            if updated:
                tree.write(strings_path, encoding="utf-8", xml_declaration=True)
                return True
        except:
            pass
        return False

    def _update_app_display_name(self, job: Job, root, src_dir: Path) -> Tuple[str, str]:
       
        old_name = self._get_current_display_name(root, src_dir)

        if not job.app_name:
            return old_name, old_name

        new_name = job.app_name.strip()

        updated = False

       
        for elem in self._get_launcher_components(root):
            label_attr = "{http://schemas.android.com/apk/res/android}label"
            current_label = elem.get(label_attr)
            if current_label:
                if current_label.startswith("@string/"):
                    res_name = current_label.split("/")[-1]
                    if self._update_string_resource(src_dir, res_name, new_name):
                        updated = True
                else:
                    elem.set(label_attr, new_name)
                    updated = True


        application = root.find("application")
        if application is not None:
            label_attr = "{http://schemas.android.com/apk/res/android}label"
            current_label = application.get(label_attr)
            if current_label:
                if current_label.startswith("@string/"):
                    res_name = current_label.split("/")[-1]
                    if self._update_string_resource(src_dir, res_name, new_name):
                        updated = True
                else:
                    application.set(label_attr, new_name)
                    updated = True

        launchers = self._get_launcher_components(root)
        if launchers and not updated:
            launchers[0].set("{http://schemas.android.com/apk/res/android}label", new_name)


        values_dirs = list((src_dir / "res").glob("values*"))
        for values_dir in values_dir:
            strings_path = values_dir / "strings.xml"
            if strings_path.exists():
                try:
                    tree = ET.parse(strings_path)
                    changed = False
                    for elem in tree.findall(".//string"):
                        name = elem.get("name")
                        if name and ("app_name" in name.lower() or "label" in name.lower()):
                            elem.text = new_name
                            changed = True
                    if changed:
                        tree.write(strings_path, encoding="utf-8", xml_declaration=True)
                        updated = True
                except:
                    pass

        return old_name, new_name

    def _extract_and_copy_icon(self, job: Job, src_dir: Path) -> Optional[str]:
        res_dir = src_dir / "res"
        if not res_dir.exists():
            return None

        density_order = ["xxxhdpi", "xxhdpi", "xhdpi", "hdpi", "mdpi"]
        possible_names = ["ic_launcher", "ic_launcher_round"]

        icon_source = None
        for density in density_order:
            for name in possible_names:
                for prefix in ["mipmap-", "drawable-"]:
                    folder = res_dir / f"{prefix}{density}"
                    if folder.exists():
                        for ext in [".png", ".webp"]:
                            candidate = folder / f"{name}{ext}"
                            if candidate.exists():
                                icon_source = candidate
                                break
                    if icon_source:
                        break
                if icon_source:
                    break
            if icon_source:
                break

        if not icon_source:
            return None

        public_output_dir = Path(os.getenv("HARDENED_APK_OUTPUT_DIR", self.download_dir))
        apk_folder = public_output_dir / f"uploads/{job.domain}/app/apk"
        apk_folder.mkdir(parents=True, exist_ok=True)

        icon_path = apk_folder / f"{job.file_name}.png"
        shutil.copy(icon_source, icon_path)

        base_url = os.getenv('PUBLIC_DOMAIN', self.base_url).rstrip('/')
        return f"{base_url}/hardened/{job.file_name}.png"

    def _harden_manifest(self, job: Job, root, tree, manifest_path: Path, original_version_code: int, original_version_name: str) -> int:
        application = root.find('application')
        if application:
            for attr in [
                '{http://schemas.android.com/apk/res/android}debuggable',
                '{http://schemas.android.com/apk/res/android}allowBackup',
                '{http://schemas.android.com/apk/res/android}fullBackupContent',
                '{http://schemas.android.com/apk/res/android}networkSecurityConfig'
            ]:
                if attr in application.attrib:
                    del application.attrib[attr]
        new_version_code = original_version_code
        random_suffix = ''.join(random.choices(string.digits, k=4))
        root.set("{http://schemas.android.com/apk/res/android}versionName", f"{original_version_name}.{random_suffix}")
        tree.write(manifest_path, encoding="utf-8", xml_declaration=True)
        return new_version_code

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
        .end method''', encoding="utf-8")

    def _add_random_text_file(self, src_dir: Path):
        
        assets_dir = src_dir / "assets"
        assets_dir.mkdir(parents=True, exist_ok=True)
        realistic_names = [
            "remote_config.txt",
            "app_params.txt",
            "fallback_strings.txt",
            "build_metadata.txt",
            "version_info.txt",
            "updated_api_call.txt",
        ]
        filename = random.choice(realistic_names)
        content_options = [
            'fallback_config=stable',
            'build_timestamp=2025-12-15',
            'Do not modify this file manually',
            'Build properties has been updated',
            'Version name was chnaged',
            'Api endpoint changed successfully',
        ]
        content = random.choice(content_options) + "\n" + ''.join(random.choices(string.ascii_letters + string.digits, k=random.randint(30, 120)))
        (assets_dir / filename).write_text(content, encoding="utf-8")

    def _add_random_dummy_image(self, src_dir: Path):
        res_dir = src_dir / "res"
        densities = ["drawable-mdpi", "drawable-hdpi", "drawable-xhdpi", "drawable-xxhdpi", "drawable-xxxhdpi"]
        chosen_density = random.choice(densities)
        folder = res_dir / chosen_density
        folder.mkdir(parents=True, exist_ok=True)

        realistic_names = [
            "ic_bg_splash.png",
            "bg_gradient.png",
            "placeholder.png",
            "default_thumb.png",
            "loading_bg.png",
            "empty_state.png",
            "banner_placeholder.png",
            "ic_empty_view.png",
            "splash_bg_placeholder.png",
            "thumb_fallback.png",
        ]
        image_name = random.choice(realistic_names)
        dummy_base64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVQYV2NgYAAAAAMAAWgmWQ0AAAAASUVORK5CYII="
        dummy_png = base64.b64decode(dummy_base64)

        (folder / image_name).write_bytes(dummy_png)

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
        
        final_apk_dir = public_output_dir / f"uploads/{job.domain}/app/apk"
        final_apk_dir.mkdir(parents=True, exist_ok=True)
        
        final_apk_path = final_apk_dir / f"{job.file_name}.apk"
        temp_apk_path = final_apk_dir / f"{job.file_name}.apk.tmp"   # ← temporary file

        public_download_url = f"{os.getenv('PUBLIC_DOMAIN', self.base_url).rstrip('/')}/hardened/{job.job_id}.apk"

        result = {
            "job_id": job.job_id,
            "original_url": job.apk_url,
            "status": "failed",
            "error": "Unknown error",
            "id": job.id,
            "icon_url": None,
            "old_display_name": "Unknown",
            "new_display_name": "Unknown"
        }

        try:
            self._download_apk(job.apk_url, temp_file)
            if not temp_file.exists() or temp_file.stat().st_size == 0:
                raise Exception("Downloaded APK is empty")

            decompile_log = self.apktool.decompile(str(temp_file), str(src_dir))
            if "ERROR" in decompile_log or "Exception" in decompile_log:
                raise Exception(decompile_log)
            

            manifest_path = src_dir / "AndroidManifest.xml"
            current_package, orig_vcode, orig_vname, tree, root = self._parse_manifest(manifest_path)
            self._cleanup_manifest_permissions(root)
            target_package = current_package
            if job.package_name_method == "random":
                target_package = self._generate_random_package()
            elif job.package_name_method == "no_random" and job.package_name and job.package_name != current_package:
                target_package = job.package_name

            if target_package != current_package:
                root.set("package", target_package)
                tree.write(manifest_path, encoding="utf-8", xml_declaration=True)
                self._rename_package(src_dir, current_package, target_package)

            old_display_name, new_display_name = self._update_app_display_name(job, root, src_dir)

            new_version_code = self._harden_manifest(job, root, tree, manifest_path, orig_vcode, orig_vname)

            self._inject_protection_stub(src_dir, target_package)

            self._add_random_text_file(src_dir)
            self._add_random_dummy_image(src_dir)

            
            icon_url = self._extract_and_copy_icon(job, src_dir)

            recompile_log = self.apktool.recompile(str(src_dir), str(rebuilt_apk))
            if not rebuilt_apk.exists():
                raise Exception(recompile_log)

            keystore = self._keystore_for_package(job)
            shutil.copy(rebuilt_apk, unsigned_apk)
            self._zipalign_apk(unsigned_apk, aligned_apk)
            
            # Sign to temporary file first
            self._sign_apk(aligned_apk, temp_apk_path, keystore)

            # Atomic rename (most filesystems make this operation atomic)
            temp_apk_path.replace(final_apk_path)

            keystore_public_path = public_output_dir / f"uploads/{job.domain}/app/apk/{job.file_name}_{job.id}.keystore"
            shutil.copy(keystore, keystore_public_path)

            base_url = os.getenv('PUBLIC_DOMAIN', self.base_url).rstrip('/')
            keystore_url = f"{base_url}/hardened/{job.file_name}_{job.id}.keystore"
            
            result.update({
                "status": "success",
                "download_url": public_download_url,
                "public_path": str(final_apk_path),
                "file_name": f"{job.file_name}.apk",
                "icon_url": icon_url,
                "old_display_name": old_display_name,
                "new_display_name": new_display_name,
                "message": "APK hardened successfully",
                "hardening_summary": "Package renamed (if requested), display name updated (if requested), icon copied, random text file + dummy PNG added, versionName randomized, versionCode preserved",
                "original_package": current_package,
                "new_package": target_package,
                "new_version_code": new_version_code,
                "icon_name": f"{job.file_name}",
                "id": job.id,
                "keystore_url": keystore_url,
            })

        except Exception as e:
            result["error"] = str(e)
            result["id"] = job.id

            # Clean up possible leftover temp file on failure
            if temp_apk_path.exists():
                try:
                    temp_apk_path.unlink()
                except:
                    pass

        finally:
            for p in [temp_file, job_folder]:
                if p and p.exists():
                    if p.is_dir():
                        shutil.rmtree(p, ignore_errors=True)
                    else:
                        p.unlink(missing_ok=True)
            pass

            try:
                requests.post(job.callback_url, json=result, timeout=15)
                print(f"[JOB {job.job_id}] Callback sent")
            except Exception as cb_e:
                print(f"[JOB {job.job_id}] Callback failed: {cb_e}")

    def start_background_hardening(self, job: Job) -> str:
        Thread(target=self.harden_and_notify, args=(job,), daemon=True).start()
        return job.job_id