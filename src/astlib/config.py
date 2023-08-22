import json
import os
from pathlib import Path
from typing import Dict

def get_ast_config() -> Dict:
    CONFIG_FILE_ENVVAR = 'GHIDRA_AST_CONFIG_FILE'

    configfile = Path(os.environ[CONFIG_FILE_ENVVAR]) if CONFIG_FILE_ENVVAR in os.environ else None
    if not configfile:
        print(f'No config file set in {CONFIG_FILE_ENVVAR}')
        return None

    with open(configfile, 'r') as f:
        config = json.load(f)

    return config

def get_ast_exportfolder() -> Path:
    config = get_ast_config()
    return Path(config['output_folder']) if config else None
