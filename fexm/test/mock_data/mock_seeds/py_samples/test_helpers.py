import os
import unittest
import unittest.mock
import shutil
from datetime import datetime

parentdir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
os.sys.path.insert(0, parentdir)
from helpers import utils


@unittest.mock.patch("requests.get")
class TestHelpers(unittest.TestCase):
    """
    Unittesting the Builder class. Mock data required.
    """

    def test_download_seed_to_folder(self, requests_get: unittest.mock.MagicMock):
        """
        Test if the Building process works.
        """
        chunks = [b"a", b"b", b"c"]
        md5_hash_chunk = "900150983cd24fb0d6963f7d28e17f72"  # The md5 hash of all the chunks saved together as string
        response_mock = unittest.mock.MagicMock()
        response_mock.iter_content.return_value = iter(chunks)
        requests_get.return_value = response_mock
        tmp_dir = "tmp/"
        if os.path.isdir(tmp_dir):
            shutil.rmtree(tmp_dir)
        os.mkdir(tmp_dir)
        download_link = "somerandomlink"  # Link not important, we have mocked the response
        filename = "Makefile"
        # This file should exists now:
        self.assertTrue(
            utils.download_seed_to_folder(download_link=download_link, to_directory=tmp_dir, filename=filename))
        self.assertTrue(os.path.isfile(tmp_dir + "/" + filename))
        self.assertEqual(utils.md5(tmp_dir + "/" + filename), md5_hash_chunk)
        # We are simulating a reponse that would be the exact same file again: Should not be downloaded.
        response_mock.iter_content.return_value = (chunks)
        self.assertFalse(utils.download_seed_to_folder(download_link=download_link, to_directory=tmp_dir,
                                                       filename=filename + "_new"))
        self.assertFalse(os.path.exists(tmp_dir + "/" + filename + "_new"))
        shutil.rmtree(tmp_dir)


@unittest.mock.patch("time.sleep")
class TestHelpers(unittest.TestCase):
    def test_check_and_wait_for_rate_limit(self, time_sleep: unittest.mock.MagicMock):
        with unittest.mock.patch('helpers.helpers.get_utc_now', return_value=datetime(2017, 10, 18, 1, 30, 0, 0)):
            utils.wait_for_rate_limit("2017-10-18T02:00:00Z")
            time_sleep.assert_called_once_with(30 * 60)
            self.assertEqual(time_sleep.call_count, 1)


if __name__ == '__main__':
    unittest.main()
