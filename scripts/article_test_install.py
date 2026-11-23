#!/usr/bin/env python3
"""One protected GitHub STAGE/CLEANUP entry; no local operational fallback."""
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import secrets
import signal
import sys
import tempfile
import time
sys.path.insert(0,str(Path(__file__).resolve().parent))

from apache_parity_bridge import _GitHubGet
from article_test_actions import authorize,control_paths,authorize_artifact,artifact_paths,download
from article_test_receiver import pins
from article_test_artifact import inspect_archive
from article_test_images import verify
from article_test_state import valid_run
from article_test_delivery import package,frame,outer_program,ssh_command,transfer,project
from article_test_host import HostRefused,require
from test_api_readonly_access import PIN_SHA256,private_file

OVERALL=1500


def collect(env):
    require(env.get('OPERATION') in ('STAGE','CLEANUP'),'ARTICLE_CONTEXT_REFUSED')
    operation=env['OPERATION'];build=pins() if operation=='STAGE' else None
    context=authorize(_GitHubGet(control_paths(env.get('GITHUB_RUN_ID'))),env)
    key=env.get('TEST_API_ADMIN_SSH_KEY');known=env.get('TEST_API_KNOWN_HOSTS')
    require(type(key) is str and 0<len(key)<=16384 and '\0' not in key,'TEST_SSH_KEY_NOT_CONFIGURED')
    require(type(known) is str and len(known)<=16384 and sha256(known.encode()).hexdigest()==PIN_SHA256,'EXACT_TEST_HOST_PIN_REQUIRED')
    run=secrets.token_hex(6) if operation=='STAGE' else env.get('CLEANUP_RUN')
    require(valid_run(run) and (operation=='CLEANUP' or env.get('CLEANUP_RUN','')==''),'ARTICLE_CONTEXT_REFUSED')
    nonce=secrets.token_hex(16);bundle=package();program=outer_program(bundle,nonce)
    with tempfile.TemporaryDirectory(prefix='jsm-article-2760-') as folder:
        directory=Path(folder);os.chmod(directory,0o700)
        identity=directory/'identity';hosts=directory/'known_hosts';archive=None;size=0;expected_images=None;expected_aliases=None
        private_file(identity,key.replace('\r\n','\n').rstrip('\n')+'\n');private_file(hosts,known)
        if operation=='STAGE':
            token=env.get('STOREFRONT_ACTIONS_READ_TOKEN')
            require(type(token) is str and re.fullmatch('[!-~]{1,4096}',token),'ARTIFACT_READ_TOKEN_NOT_CONFIGURED')
            api=_GitHubGet(artifact_paths(build),token=token);size=authorize_artifact(api,build)
            archive=directory/'artifact.zip'
            download(build,token,archive,size,time.monotonic()+300)
            inspected=inspect_archive(archive,build);expected_images=(inspected.app_image,inspected.mysql_image)
            proof=verify(archive,inspected,time.monotonic()+180);expected_aliases=proof.aliases
        prefix=frame(operation,run,nonce,context['control_sha'],build,size)
        raw=transfer(ssh_command(identity,hosts,program),prefix,archive,time.monotonic()+720)
        result=project(raw,nonce,operation,run,build,expected_images,expected_aliases)
    return dict(result,environment='ISOLATED_SYNTHETIC_TEST',resource='gce:dark-berm-508215-d2:asia-northeast1-a:150919059249400713',
        control_sha=context['control_sha'],workflow_run='https://github.com/JSMJapan/jsm-release-control/actions/runs/'+context['run_id'])


SAFE=frozenset(('ARTIFACT_NOT_PINNED','ARTIFACT_READ_TOKEN_NOT_CONFIGURED','CONTROL_CONTEXT_REFUSED',
    'CONTROL_APPROVAL_REFUSED','PRIVATE_ARTIFACT_SCOPE_REFUSED','PRIVATE_DOWNLOAD_REFUSED','PRIVATE_DOWNLOAD_DEADLINE',
    'TEST_SSH_KEY_NOT_CONFIGURED','EXACT_TEST_HOST_PIN_REQUIRED','ARTICLE_CONTEXT_REFUSED','ARTICLE_BUNDLE_REFUSED',
    'ARTICLE_DELIVERY_REFUSED','ARTICLE_DELIVERY_DEADLINE','ARTICLE_RECEIPT_REFUSED','ARTICLE_ARTIFACT_REFUSED',
    'ARTICLE_IMAGE_ENVELOPE_REFUSED','ARTICLE_IMAGE_DEADLINE','ARTICLE_OVERALL_DEADLINE'))


def main():
    def expired(*_):raise HostRefused('ARTICLE_OVERALL_DEADLINE')
    signal.signal(signal.SIGALRM,expired);signal.alarm(OVERALL)
    try:
        result=collect(os.environ)
        print(json.dumps(result,sort_keys=True,separators=(',',':')))
        return 0 if result['status'] in ('STAGED_LOCAL_ONLY','CLEANED') else 1
    except BaseException as error:
        reason=error.args[0] if len(error.args)==1 and type(error.args[0]) is str and error.args[0] in SAFE else 'CONTROL_PREFLIGHT_REFUSED'
        print(json.dumps({'status':'BLOCKED','reason':reason},sort_keys=True,separators=(',',':')));return 1
    finally:signal.alarm(0)

if __name__=='__main__':raise SystemExit(main())
