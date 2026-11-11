import hashlib
import os
import tempfile
import unittest

from analyzers.utils import fmt_size, sha256_file


class TestUtils(unittest.TestCase):
    def test_fmt_size(self):
        self.assertEqual(fmt_size(0), "0.0 B")
        self.assertEqual(fmt_size(500), "500.0 B")
        self.assertEqual(fmt_size(1024), "1.0 KB")
        self.assertEqual(fmt_size(1536), "1.5 KB")
        self.assertEqual(fmt_size(1024 * 1024), "1.0 MB")
        self.assertEqual(fmt_size(1024 * 1024 * 1024), "1.0 GB")

    def test_sha256_file(self):
        sample_data = b"androidsec test content 12345"
        expected = hashlib.sha256(sample_data).hexdigest()

        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(sample_data)
            tf_path = tf.name

        try:
            actual = sha256_file(tf_path)
            self.assertEqual(actual, expected)
        finally:
            if os.path.exists(tf_path):
                os.remove(tf_path)


if __name__ == "__main__":
    unittest.main()
