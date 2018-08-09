from unittest import TestCase
import os

parentdir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
os.sys.path.insert(0, parentdir)
from configfinder import minimzer
import shutil
import json


class TestMinize(TestCase):
    def test_minize_fast_binary(self):
        try:
            os.makedirs("testvolume/main")
        except OSError:
            pass
        m = minimzer.minize(parameter="@@", seeds_dir="mock_data/mock_seeds/jpg_samples",
                            binary_path="mock_data/input_mock/jpg_binary/main", package=None, volume_path="testvolume",
                            afl_config_file_name="test.afl_config", tmin_total_time=1000)
        afl_min_dict = {}
        with open("testvolume/main/test.afl_config") as fp:
            afl_min_dict = json.load(fp)
        min_seeds = afl_min_dict["min_seeds_dir"]
        for file in os.listdir(min_seeds):
            print("Minimized file size:", os.path.getsize(os.path.join(min_seeds, file)))
            print("Original file size", os.path.getsize(os.path.join("mock_data/mock_seeds/jpg_samples", file)))
        if os.path.exists("testvolume"):
            shutil.rmtree("testvolume")

    def test_slow_binary(self):
        try:
            os.makedirs("testvolume/main")
        except OSError:
            pass
        m = minimzer.minize(parameter="@@", seeds_dir="mock_data/mock_seeds/jpg_samples",
                            binary_path="mock_data/input_mock/jpg_slow_binary/main", package=None,
                            volume_path="testvolume", afl_config_file_name="test.afl_config", tmin_total_time=4)
        afl_min_dict = {}
        with open("testvolume/main/test.afl_config") as fp:
            afl_min_dict = json.load(fp)
        min_seeds = afl_min_dict["min_seeds_dir"]
        for file in os.listdir(min_seeds):
            print("Slow Binary: Minimized file size:", os.path.getsize(os.path.join(min_seeds, file)))
            print("Fast Binary: Original file size",
                  os.path.getsize(os.path.join("mock_data/mock_seeds/jpg_samples", file)))
        if os.path.exists("testvolume"):
            shutil.rmtree("testvolume")
