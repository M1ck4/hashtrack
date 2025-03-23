import configparser
import os

DEFAULT_CONFIG_PATH = "config.ini"

DEFAULTS = {
    'virustotal': {
        'api_key': '',
        'rate_limit_per_min': '4',
        'daily_quota': '500',
        'use_cache': 'yes',
        'cache_expiry_days': '7'
    },
    'output': {
        'default_folder': 'logs',
        'keep_days': '7'
    },
    'options': {
        'quiet_default': 'no'
    }
}

def load_config(path: str = DEFAULT_CONFIG_PATH) -> configparser.ConfigParser:
    config = configparser.ConfigParser()

    # Write default config if it doesn't exist
    if not os.path.exists(path):
        for section, values in DEFAULTS.items():
            config[section] = values
        with open(path, 'w') as f:
            config.write(f)
    else:
        config.read(path)
        # Fill in any missing defaults
        for section, values in DEFAULTS.items():
            if not config.has_section(section):
                config.add_section(section)
            for key, val in values.items():
                if not config.has_option(section, key):
                    config.set(section, key, val)

    return config

def get_vt_api_key(config: configparser.ConfigParser) -> str:
    return config.get('virustotal', 'api_key', fallback='')

def get_vt_rate_limit(config: configparser.ConfigParser) -> int:
    return int(config.get('virustotal', 'rate_limit_per_min', fallback='4'))

def get_vt_daily_quota(config: configparser.ConfigParser) -> int:
    return int(config.get('virustotal', 'daily_quota', fallback='500'))

def get_vt_use_cache(config: configparser.ConfigParser) -> bool:
    return config.get('virustotal', 'use_cache', fallback='yes').lower() in ('yes', 'true', '1')

def get_vt_cache_expiry_days(config: configparser.ConfigParser) -> int:
    return int(config.get('virustotal', 'cache_expiry_days', fallback='7'))

def get_keep_days(config: configparser.ConfigParser) -> int:
    return int(config.get('output', 'keep_days', fallback='7'))

def get_output_folder(config: configparser.ConfigParser) -> str:
    return config.get('output', 'default_folder', fallback='logs')

def quiet_mode_default(config: configparser.ConfigParser) -> bool:
    return config.get('options', 'quiet_default', fallback='no').lower() in ('yes', 'true', '1')