import os
import platform
import subprocess
import webbrowser
import getpass
import json
from .exceptions import EnvironmentNotFoundException
from urllib.parse import urlparse
from typing import Union, List
from .const import __version__, PHASE_CLOUD_API_HOST, cross_env_pattern, local_ref_pattern


def get_default_user_token() -> str:
    """
    Fetch the default user's personal access token from the config file in PHASE_SECRETS_DIR.

    Returns:
    - str: The default user's personal access token.

    Raises:
    - ValueError: If the config file is not found, the default user's ID is missing, or the token is not set.
    """
    config_file_path = os.path.join(PHASE_SECRETS_DIR, 'config.json')
    
    if not os.path.exists(config_file_path):
        raise ValueError("Config file not found. Please login with phase auth or supply a PHASE_SERVICE_TOKEN as an environment variable.")
    
    with open(config_file_path, 'r') as f:
        config_data = json.load(f)

    default_user_id = config_data.get("default-user")
    if not default_user_id:
        raise ValueError("Default user ID is missing in the config file.")

    for user in config_data.get("phase-users", []):
        if user['id'] == default_user_id:
            token = user.get("token")
            if not token:
                raise ValueError(f"Token for the default user (ID: {default_user_id}) is not found in the config file.")
            return token

    raise ValueError("Default user not found in the config file.")


def phase_get_context(user_data, app_name=None, env_name=None):
    """
    Get the context (ID, name, and publicKey) for a specified application and environment or the default application and environment.

    Parameters:
    - user_data (dict): The user data from the API response.
    - app_name (str, optional): The name (or partial name) of the desired application.
    - env_name (str, optional): The name (or partial name) of the desired environment.

    Returns:
    - tuple: A tuple containing the application's name, application's ID, environment's name, environment's ID, and publicKey.

    Raises:
    - ValueError: If no matching application or environment is found.
    """

    # 2. If env_name isn't explicitly provided, use the default
    default_env_name = "Development"
    app_id = None
    env_name = env_name or default_env_name

    # 3. Match the application using app_id or find the best match for partial app_name
    try:
        if app_name:
            matching_apps = [app for app in user_data["apps"] if app_name.lower() in app["name"].lower()]
            if not matching_apps:
                raise ValueError(f"🔍 No application found with the name '{app_name}'.")
            # Sort matching applications by the length of their names, shorter names are likely to be more specific matches
            matching_apps.sort(key=lambda app: len(app["name"]))
            application = matching_apps[0]
        elif app_id:
            application = next((app for app in user_data["apps"] if app["id"] == app_id), None)
            if not application:
                raise ValueError(f"🔍 No application found with the name '{app_name_from_config}' and ID: '{app_id}'.")
        else:
            raise ValueError("🤔 No application context provided. Please run 'phase init' or pass the '--app' flag followed by your application name.")

        # 4. Attempt to match environment with the exact name or a name that contains the env_name string
        environment = next((env for env in application["environment_keys"] if env_name.lower() in env["environment"]["name"].lower()), None)

        if not environment:
            raise EnvironmentNotFoundException(env_name)

        # Return application name, application ID, environment name, environment ID, and public key
        return (application["name"], application["id"], environment["environment"]["name"], environment["environment"]["id"], environment["identity_key"])
    except StopIteration:
        raise ValueError("🔍 Application or environment not found.")


def normalize_tag(tag):
    """
    Normalize a tag by replacing underscores with spaces.

    Args:
        tag (str): The tag to normalize.

    Returns:
        str: The normalized tag.
    """
    return tag.replace('_', ' ').lower()


def tag_matches(secret_tags, user_tag):
    """
    Check if the user-provided tag partially matches any of the secret tags.

    Args:
        secret_tags (list): The list of tags associated with a secret.
        user_tag (str): The user-provided tag to match.

    Returns:
        bool: True if there's a partial match, False otherwise.
    """
    normalized_user_tag = normalize_tag(user_tag)
    for tag in secret_tags:
        normalized_secret_tag = normalize_tag(tag)
        if normalized_user_tag in normalized_secret_tag:
            return True
    return False


def get_user_agent():
    """
    Constructs a user agent string containing information about the CLI's version, 
    the operating system, its version, its architecture, and the local username with machine name.
    
    Returns:
        str: The constructed user agent string.
    """

    details = []
    
    # Get CLI version
    try:
        cli_version = f"phase-python-sdk/{__version__}"
        details.append(cli_version)
    except:
        pass

    # Get OS and version
    try:
        os_type = platform.system()  # e.g., Windows, Linux, Darwin (for macOS)
        os_version = platform.release()
        details.append(f"{os_type} {os_version}")
    except:
        pass

    # Get architecture
    try:
        architecture = platform.machine()
        details.append(architecture)
    except:
        pass

    # Get username and hostname
    try:
        username = getpass.getuser()
        hostname = platform.node()
        user_host_string = f"{username}@{hostname}"
        details.append(user_host_string)
    except:
        pass

    user_agent_str = ' '.join(details)
    return user_agent_str