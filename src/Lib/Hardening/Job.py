import uuid
import xml.etree.ElementTree as ET
from typing import Optional
class Job:
    """
    Encapsulates all parameters for a hardening job to reduce method parameter counts.
    Follows single responsibility: holds job configuration data.
    """
    def __init__(
        self,
        apk_url: str,
        callback_url: str,
        id: int,
        domain: str,
        file_name: str,
        package_name_method: str,
        package_name: Optional[str] = None,
        current_version: Optional[int] = None,
        app_name: Optional[str] = None
    ):
        self.job_id = str(uuid.uuid4())
        self.apk_url = apk_url
        self.callback_url = callback_url
        self.id = id
        self.domain = domain
        self.file_name = file_name
        self.package_name_method = package_name_method
        self.package_name = package_name
        self.current_version = current_version
        self.app_name = app_name