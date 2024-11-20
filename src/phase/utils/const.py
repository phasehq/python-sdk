import os
import re

__version__ = "2.0.1"
__ph_version__ = "v1"


SECRET_REF_REGEX = re.compile(r'\$\{([^}]+)\}')


PHASE_CLOUD_API_HOST = "https://console.phase.dev"

pss_user_pattern = re.compile(r"^pss_user:v(\d+):([a-fA-F0-9]{64}):([a-fA-F0-9]{64}):([a-fA-F0-9]{64}):([a-fA-F0-9]{64})$")
pss_service_pattern = re.compile(r"^pss_service:v(\d+):([a-fA-F0-9]{64}):([a-fA-F0-9]{64}):([a-fA-F0-9]{64}):([a-fA-F0-9]{64})$")

cross_env_pattern = re.compile(r"\$\{(.+?)\.(.+?)\}")
local_ref_pattern = re.compile(r"\$\{([^.]+?)\}")

