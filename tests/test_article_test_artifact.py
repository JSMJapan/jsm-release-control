"""Synthetic private-artifact envelopes; never contain the website/images."""
from hashlib import sha256
from io import BytesIO
import json
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from zipfile import ZipFile,ZipInfo,ZIP_STORED

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from article_test_artifact import Build, ArtifactRefused, inspect_archive, extract_metadata, MEMBERS


class ArtifactTests(unittest.TestCase):
    def package(self,change=None):
        source=dict(status='SOURCE_INPUTS_VERIFIED',environment='TEST',source_commit='0184fcbc7bdbb0ca18da842532297bd12f3b557b',source_tree='b43fea383b8acfbda07562ee7a32fbc2fe98f05e')
        schema=b'CREATE TABLE synthetic_fixture (id INT);\n';seed=b'INSERT INTO synthetic_fixture VALUES (1);\n'
        proof=dict(status='CI_NATIVE_PASS',network='LOOPBACK_ONLY',database='FIVE_SYNTHETIC_ROWS',grants='SELECT_TWO_TABLES',cleanup='VERIFIED',api=5,ssr=10,negative=8,
                   schema_sha256=sha256(schema).hexdigest(),seed_sha256=sha256(seed).hexdigest())
        rows={'source.json':json.dumps(source).encode(),'schema.sql':schema,'seed.sql':seed,'acceptance.json':json.dumps(proof).encode(),
              'build-commit':b'a'*40+b'\n','app-image-id':b'sha256:'+b'b'*64+b'\n','mysql-image-id':b'sha256:'+b'c'*64+b'\n','images.tar.gz':b'synthetic compressed images'}
        if change:change(rows)
        rows['SHA256SUMS']=''.join(sha256(value).hexdigest()+'  '+name+'\n' for name,value in sorted(rows.items())).encode()
        out=BytesIO()
        with ZipFile(out,'w',compression=ZIP_STORED) as archive:
            for name,value in rows.items():archive.writestr(name,value)
        raw=out.getvalue();build=Build('a'*40,'123','456',sha256(raw).hexdigest())
        return raw,build

    def test_actual_reader_checks_all_members_and_extracts_only_exact_names(self):
        raw,build=self.package()
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);path=root/'artifact.zip';path.write_bytes(raw)
            got=inspect_archive(path,build)
            self.assertEqual(set(got.members),set(MEMBERS));self.assertEqual(got.app_image,'sha256:'+'b'*64)
            self.assertEqual(got.source_sha,'0184fcbc7bdbb0ca18da842532297bd12f3b557b')
            self.assertEqual(got.image_archive_bytes,len(b'synthetic compressed images'))

    def test_extraction_reopens_nofollow_rechecks_digest_and_never_overwrites(self):
        raw,build=self.package()
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);path=root/'a.zip';path.write_bytes(raw);output=root/'metadata';output.mkdir()
            inspected=inspect_archive(path,build);extract_metadata(path,output,inspected)
            self.assertEqual({p.name for p in output.iterdir()},set(MEMBERS)-{'images.tar.gz','SHA256SUMS'})
            with self.assertRaises(ArtifactRefused):extract_metadata(path,output,inspected)
            other=root/'other.zip';other.write_bytes(raw);path.unlink();path.symlink_to(other)
            with self.assertRaises(ArtifactRefused):extract_metadata(path,output,inspected)
            path.unlink();path.write_bytes(raw+b'CANARY-SWAPPED')
            with self.assertRaises(ArtifactRefused):extract_metadata(path,output,inspected)

    def test_changed_source_build_proof_hash_and_member_refuse(self):
        mutations=[lambda r:r.update({'build-commit':b'd'*40+b'\n'}),lambda r:r.update({'acceptance.json':b'{}'}),
                   lambda r:r.update({'source.json':b'{"source_commit":"PRIVATE"}'}),lambda r:r.update({'../schema.sql':b'PRIVATE'}),
                   lambda r:r.update({'app-image-id':b'PRIVATE'})]
        for mutate in mutations:
            raw,build=self.package(mutate)
            with tempfile.TemporaryDirectory() as temporary:
                path=Path(temporary)/'a.zip';path.write_bytes(raw)
                with self.assertRaises(ArtifactRefused):inspect_archive(path,build)

    def test_archive_hash_and_typed_build_pins_required(self):
        raw,build=self.package()
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/'a.zip';path.write_bytes(raw+b'PRIVATE')
            with self.assertRaises(ArtifactRefused):inspect_archive(path,build)
        for args in [('a'*40,True,'2','b'*64),('PRIVATE','1','2','b'*64),('a'*40,'1','2','PRIVATE')]:
            with self.assertRaises(ArtifactRefused):Build(*args)

if __name__=='__main__':unittest.main()
