"""Actual PHP syntax/coordinator on CI; fake connection never opens DB."""
from pathlib import Path
import shutil
import subprocess
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]

class NativePhpTests(unittest.TestCase):
    def test_native_php_syntax_and_pre_sql_barriers(self):
        php=shutil.which('php')
        if not php:
            if sys.platform.startswith('linux'):self.fail('Native PHP is required on CI')
            self.skipTest('Native PHP unavailable locally; required on Linux CI')
        for file in (ROOT/'scripts').glob('test_db_runtime*.php'):
            result=subprocess.run([php,'-l',str(file)],capture_output=True,timeout=5)
            self.assertEqual(result.returncode,0,'PHP_SYNTAX_REFUSED: '+file.name)
        result=subprocess.run([php,str(ROOT/'tests/runtime_php_fixture.php')],capture_output=True,timeout=5)
        self.assertEqual(result.returncode,0,'NATIVE_PHP_FIXTURE_FAILED')
        self.assertEqual(result.stdout,b'NATIVE_PHP_FIXTURES_PASS\n')
        self.assertEqual(result.stderr,b'')

if __name__=='__main__':unittest.main()
