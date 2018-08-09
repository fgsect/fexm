from unittest import TestCase
import os

parentdir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
os.sys.path.insert(0, parentdir)
import builders.builder


class TestBuilder(TestCase):
    def test_install_opt_depens_for_pacman(self):
        b = builders.builder.Builder("openjpeg")
        # b.install_opt_depends_for_pacman()
