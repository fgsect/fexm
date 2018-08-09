import json
import sys
import traceback

import importlib

import functools
import os
from typing import *

from helpers.typechecker import checked

default_config = {
    "seeds": "/seeds",
    "out_dir": "/data",
    "build_folder": "~",
    "fuzz_duration": 45,
    "base_image": "pacmanfuzzer",
    "max_build_size": 1000000000000,
    "max_size": 10000000000,
    "use_asan": True,
    "force": True,  # TODO: Should be commandline switch.
    "exec_timeout": "1000+",
    "fuzzing_cores_per_binary": 1,
}


# noinspection PyUnusedLocal
@checked
def check_types(
        name: str,
        # defaults
        fuzz_manager: str,
        json_name: str,
        seeds: str,
        out_dir: str,
        build_folder: str,
        fuzz_duration: int,
        base_image: str,
        max_build_size: int,
        max_size: int,
        use_asan: bool,
        force: bool,
        # pacmanfuzzer
        exec_timeout: Union[int, str],
        fuzzing_cores_per_binary: Optional[int],
        packages_file: Optional[str] = None,

        # Autofilled and will be overwritten.
        manager: Optional[type(os)] = None,
        fuzz_func: Optional[Callable] = None,
        **kwargs
):
    if kwargs:
        print("Unexpected values in config: {}".format(kwargs))


def apply_defaults_and_validate(config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Applies defaults to unset config entries and checks types for all others.
    :param config:
    :return:
    """
    ret = dict(default_config)
    ret.update(config)
    check_types(**ret)
    return ret


def load_config(config_path: str) -> dict:
    """
    Loads a config and initialized the fuzz manager into config[fuzzer].
    The config will have a .fuzz() function starting the fuzz manager as shorthand.
    :param config_path: the path to load a json from
    :return: the parsed config with attached fuzz() function
    """
    try:
        if not os.path.isfile(config_path):
            raise ValueError("No valid file found at {}".format(config_path))
        with open(config_path, "r") as f:
            config = json.load(f)
            method = config["fuzz_manager"]
            config["json_name"] = os.path.basename(config_path)

            if "build_folder" not in config:
                config["build_folder"] = os.path.dirname(os.path.abspath(config_path))

            config = apply_defaults_and_validate(config)
    except Exception as ex:
        traceback.print_exc(file=sys.stderr)
        raise ValueError("Could not load valid config at {} ({}).".format(config_path, ex), ex)

    try:
        manager = importlib.import_module("fuzz_managers.{}".format(method))
        if "fuzz" not in manager.__dict__:
            raise ImportError("Not a valid fuzz manager (no fuzz() function)")
    except ImportError as ex:
        raise ValueError(
            "Fuzz manager {} could not be found (config loaded from {}). "
            "See available fuzz managers in ./fuzz_managers.".format(method, config_path), ex)

    fuzz_func = functools.partial(manager.fuzz, config)

    config["manager"] = manager  # This now contains a module, not a string.
    config["fuzz_func"] = fuzz_func
    return config
