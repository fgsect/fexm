from unittest import TestCase
import os

parentdir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
os.sys.path.insert(0, parentdir)
import helpers.utils


class TestInference_possible(TestCase):
    def test_inference_possible(self):
        self.assertTrue(helpers.utils.inference_possible("file"))
        self.assertTrue(helpers.utils.inference_possible("wpaclean"))
