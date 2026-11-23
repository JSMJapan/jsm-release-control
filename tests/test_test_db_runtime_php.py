"""Actual PHP syntax/coordinator on CI; fake connection never opens DB."""
from pathlib import Path
import hashlib
import json
import re
import shutil
import subprocess
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from test_db_runtime_fastcgi import request_params

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
        diagnostic=result.stderr.decode('ascii',errors='ignore').strip()
        diagnostic=diagnostic if re.fullmatch(r'PHP_FIXTURE:[A-Z_]+:[A-Z_]+:[0-9]{1,5}',diagnostic) else 'CLOSED_REFUSAL'
        self.assertEqual(result.returncode,0,'NATIVE_PHP_FIXTURE_FAILED:'+diagnostic)
        self.assertEqual(result.stdout,b'NATIVE_PHP_FIXTURES_PASS\n')
        self.assertEqual(result.stderr,b'')
        provenance=json.loads((ROOT/'tests/fixtures/runtime_yii_provenance.json').read_text())
        for entry in provenance.values():
            self.assertEqual(hashlib.sha256((ROOT/'tests/fixtures'/entry['fixture_file']).read_bytes()).hexdigest(),entry['fixture_sha256'])
        result=subprocess.run([php,str(ROOT/'tests/runtime_yii_fixture.php'),json.dumps(request_params('a'*32,'b'*64,'c'*32,{'path':'/run/jsm-db-2760-'+'a'*32}))],capture_output=True,timeout=5)
        self.assertEqual(result.returncode,0,'NATIVE_YII_FIXTURE_FAILED')
        self.assertEqual(result.stdout,b'YII_NATIVE_FIXTURES_PASS\n')
        self.assertEqual(result.stderr,b'')
        for mode in ('valid','canary','alias','resolver'):
            result=subprocess.run([php,str(ROOT/'tests/runtime_models_fixture.php'),mode],capture_output=True,timeout=5)
            self.assertEqual(result.returncode,0,'NATIVE_MODELS_FIXTURE_FAILED:'+mode)
            self.assertEqual(result.stdout,b'MODELS_NATIVE_FIXTURES_PASS\n')
            self.assertEqual(result.stderr,b'')
        self.assertEqual(result.stderr,b'')

if __name__=='__main__':unittest.main()
