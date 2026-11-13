import sys, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import services as s

class TestBot(unittest.TestCase):
    def test_secrets(self):
        r = s.scan_secrets("AWS=AKIAIOSFODNN7EXAMPLE")
        self.assertFalse(r["safe_to_publish"])
    def test_clean(self):
        self.assertTrue(s.scan_secrets("hola mundo")["safe_to_publish"])
    def test_solidity(self):
        self.assertEqual(s.audit_solidity("pragma solidity ^0.8.0; tx.origin;")["verdict"], "REJECT")

if __name__ == "__main__": unittest.main()
