import os
import json
from venv import logger
import requests
import pkg_resources
import subprocess
from datetime import datetime, timedelta

__dir__ = os.path.abspath(os.path.dirname(__file__))
version = subprocess.check_output(
    [
        "python3",
        os.path.join(
            __dir__,
            "__version__.py",
        ),
    ],
    encoding="utf8",
)

def check_for_updates(logger):
    package_name = 'ipmgr'
    current_version = subprocess.check_output(
        [
            "python3",
            os.path.join(
                __dir__,
                "__version__.py",
            ),
        ],
        encoding="utf8",
    )

    config_file = os.path.join(os.path.expanduser('~'), '.ipm', 'ipm_package.json')

    def load_last_check():
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                return json.load(f)
        return {}

    def save_last_check(data):
        with open(config_file, 'w') as f:
            json.dump(data, f)

    config = load_last_check()
    last_check = config.get('last_check')

    if last_check:
        last_check_date = datetime.strptime(last_check, '%Y-%m-%d')
        if datetime.now() - last_check_date < timedelta(days=1):
            return

    try:
        response = requests.get(f'https://pypi.org/pypi/{package_name}/json')
        response.raise_for_status()
        latest_version = response.json()['info']['version']

        if current_version < latest_version:
            logger.print_warn(f"A new version ({latest_version}) of {package_name} is available. "
                  f"You're using version {current_version}. Please update using 'pip install --upgrade {package_name}'.")

        config['last_check'] = datetime.now().strftime('%Y-%m-%d')
        save_last_check(config)
    except requests.exceptions.RequestException as e:
        logger.print_err(f"Could not check for updates: {e}")