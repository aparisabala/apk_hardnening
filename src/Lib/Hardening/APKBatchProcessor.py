import os
import time
import uuid
import shutil
import subprocess
from src.Lib.Hardening.APKTool import APKTool
from flask import Flask, request, jsonify
import random
import string
class APKBatchProcessor:
    def __init__(self, jobs_dir, download_dir, apktool: APKTool):
        self.jobs_dir = jobs_dir
        self.download_dir = download_dir
        self.apktool = apktool

        os.makedirs(jobs_dir, exist_ok=True)
        os.makedirs(download_dir, exist_ok=True)

    def download_apk(self, url, save_path):
        cmd = f"curl -L \"{url}\" -o \"{save_path}\""
        return self.apktool.run(cmd)

    def process_single(self, apk_path):
        job_id = str(uuid.uuid4())
        job_folder = os.path.join(self.jobs_dir, job_id)

        src_dir = os.path.join(job_folder, "src")
        rebuilt_apk = os.path.join(job_folder, "rebuilt.apk")

        os.makedirs(job_folder, exist_ok=True)
        log1 = self.apktool.decompile(apk_path, src_dir)
    
        log2 = self.apktool.recompile(src_dir, rebuilt_apk)
        
        final_name = f"{job_id}.apk"
        final_path = os.path.join(self.download_dir, final_name)

        shutil.copy(rebuilt_apk, final_path)

        return {
            "job_id": job_id,
            "download_url": f"https://yourdomain.com/downloads/{final_name}",
            "log": log1 + "\n" + log2
        }

    def process_batch(self, apk_urls, interval_min):
        results = []

        for idx, url in enumerate(apk_urls):
            local_file = os.path.join(self.jobs_dir, f"apk_{self.generate_file_name()}.apk")

            # Download
            self.download_apk(url, local_file)

            # Process 1 file
            res = self.process_single(local_file)
            results.append(res)

            # Wait between jobs
            time.sleep(interval_min * 60)

        return results
    
    def generate_file_name(self):
        part1 = ''.join(random.sample(string.ascii_lowercase, 4))
        part2 = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
        return f"{part1}_{part2}"
