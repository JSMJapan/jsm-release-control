"""Fixed GitHub authorization and private artifact delivery, no VM operations."""
from hashlib import sha256
import http.client
import os
import re
import ssl
import time
from urllib.parse import urlsplit

from apache_parity_bridge import _GitHubGet, Refused, strict_json
from test_installer_capture_encrypted import GH_REPO, GH_ENV
from hostinger_preflight import policy_ready
from article_test_artifact import Build, ARCHIVE_LIMIT

REPO='JSMJapan/jsm-release-control'
SOURCE_REPO='JSMJapan/jsm-storefront'
SOURCE_API='/repos/'+SOURCE_REPO
WORKFLOW='.github/workflows/article-test-install-2760.yml'
PACKAGE_WORKFLOW='.github/workflows/article-test-package-2760.yml'
ENVIRONMENT_ID=26702164832
OWNER_ID=327623967
FIXED=dict(GITHUB_REPOSITORY=REPO,GITHUB_ACTOR='JSMJapan',GITHUB_TRIGGERING_ACTOR='JSMJapan',
    GITHUB_REF='refs/heads/main',GITHUB_EVENT_NAME='workflow_dispatch',GITHUB_RUN_ATTEMPT='1',
    GITHUB_SERVER_URL='https://github.com',GITHUB_API_URL='https://api.github.com',GITHUB_JOB='install',
    GITHUB_WORKFLOW_REF=REPO+'/'+WORKFLOW+'@refs/heads/main')


class ActionsRefused(ValueError):pass


def require(value,reason):
    if not value:raise ActionsRefused(reason)


def control_paths(run_id):
    require(type(run_id) is str and re.fullmatch('[1-9][0-9]{0,14}',run_id),'CONTROL_CONTEXT_REFUSED')
    run=GH_REPO+'/actions/runs/'+run_id
    return (GH_REPO,GH_ENV,GH_ENV+'/deployment-branch-policies',GH_REPO+'/branches/main',
            GH_REPO+'/actions/workflows/'+WORKFLOW.rsplit('/',1)[1],run,run+'/approvals')


def authorize(api,env):
    try:return _authorize(api,env)
    except ActionsRefused:raise
    except Exception:raise ActionsRefused('CONTROL_CONTEXT_REFUSED') from None


def _authorize(api,env):
    sha=env.get('GITHUB_SHA');run_id=env.get('GITHUB_RUN_ID')
    require(all(env.get(k)==v for k,v in FIXED.items()) and type(sha) is str and re.fullmatch('[0-9a-f]{40}',sha)
            and env.get('GITHUB_WORKFLOW_SHA')==sha and env.get('APPROVED_SHA')==sha,'CONTROL_CONTEXT_REFUSED')
    paths=control_paths(run_id)
    repository,environment,branches=(api.get_json(path) for path in paths[:3])
    policy_ready(repository,environment,branches)  # Existing main pure protection guard.
    require(type(repository.get('id')) is int and repository['id']==1427965640
            and repository.get('owner',{}).get('login')=='JSMJapan'
            and type(repository['owner'].get('id')) is int and repository['owner']['id']==OWNER_ID,'CONTROL_APPROVAL_REFUSED')
    require(type(environment.get('id')) is int and environment['id']==ENVIRONMENT_ID,'CONTROL_APPROVAL_REFUSED')
    main,workflow,run,approvals=(api.get_json(path) for path in paths[3:])
    require(main.get('protected') is True and main.get('name')=='main' and main.get('commit',{}).get('sha')==sha,
            'CONTROL_CONTEXT_REFUSED')
    require(workflow.get('path')==WORKFLOW and workflow.get('state')=='active' and type(workflow.get('id')) is int,
            'CONTROL_CONTEXT_REFUSED')
    require(type(run) is dict and run.get('head_sha')==sha and run.get('head_branch')=='main'
            and run.get('event')=='workflow_dispatch' and type(run.get('run_attempt')) is int and run['run_attempt']==1
            and all(run.get(k,{}).get('full_name')==REPO and run[k].get('private') is False
                    and run[k].get('id')==repository['id'] for k in ('repository','head_repository'))
            and run.get('path')==WORKFLOW and run.get('workflow_id')==workflow['id'] and run.get('status')=='in_progress'
            and type(run.get('id')) is int and run['id']==int(run_id)
            and all(run.get(k,{}).get('login')=='JSMJapan' and type(run[k].get('id')) is int
                    and run[k]['id']==OWNER_ID for k in ('actor','triggering_actor')),'CONTROL_CONTEXT_REFUSED')
    require(type(approvals) is list and len(approvals)==1,'CONTROL_APPROVAL_REFUSED')
    approval=approvals[0]
    require(approval.get('state')=='approved' and approval.get('user',{}).get('login')=='JSMJapan'
            and type(approval.get('user',{}).get('id')) is int and approval['user']['id']==OWNER_ID
            and type(approval.get('environments')) is list and len(approval['environments'])==1
            and type(approval['environments'][0].get('id')) is int and approval['environments'][0]['id']==ENVIRONMENT_ID
            and approval['environments'][0].get('name')=='test-api-readonly-access','CONTROL_APPROVAL_REFUSED')
    return dict(control_sha=sha,run_id=run_id)


def artifact_paths(build):
    return (SOURCE_API,SOURCE_API+'/actions/runs/'+build.run_id,
            SOURCE_API+'/actions/runs/'+build.run_id+'/artifacts',
            SOURCE_API+'/actions/runs/'+build.run_id+'/attempts/1/jobs?per_page=100',
            SOURCE_API+'/actions/artifacts/'+build.artifact_id)


def authorize_artifact(api,build):
    try:return _authorize_artifact(api,build)
    except ActionsRefused:raise
    except Exception:raise ActionsRefused('PRIVATE_ARTIFACT_SCOPE_REFUSED') from None


def _authorize_artifact(api,build):
    require(type(build) is Build,'ARTIFACT_NOT_PINNED')
    repo,run,listing,jobs,item=(api.get_json(path) for path in artifact_paths(build))
    require(repo.get('full_name')==SOURCE_REPO and repo.get('private') is True
            and type(repo.get('id')) is int and repo['id']>0
            and repo.get('owner',{}).get('login')=='JSMJapan' and type(repo['owner'].get('id')) is int and repo['owner']['id']==OWNER_ID,'PRIVATE_ARTIFACT_SCOPE_REFUSED')
    require(run.get('head_sha')==build.sha and run.get('path')==PACKAGE_WORKFLOW
            and run.get('event')=='pull_request' and run.get('status')=='completed' and run.get('conclusion')=='success'
            and type(run.get('id')) is int and run['id']==int(build.run_id)
            and type(run.get('run_attempt')) is int and run['run_attempt']==1
            and all(type(run.get(k,{}).get('id')) is int and run[k]['id']==repo['id']
                    and run[k].get('full_name')==SOURCE_REPO and run[k].get('private') is True
                    for k in ('repository','head_repository')),'PRIVATE_ARTIFACT_SCOPE_REFUSED')
    required_steps=('Check out the reviewed package source','Check out the fixed article candidate',
        'Prepare reviewed sources and separate schema and seed','Build only the disposable article image',
        'Run native MySQL and article HTTP acceptance without external networking',
        'Create a checksummed offline deployment artifact','Upload the verified isolated package to private GitHub Actions')
    require(type(jobs) is dict and jobs.get('total_count')==1 and type(jobs.get('total_count')) is int
            and type(jobs.get('jobs')) is list and len(jobs['jobs'])==1,'PRIVATE_ARTIFACT_SCOPE_REFUSED')
    job=jobs['jobs'][0]
    require(type(job) is dict and job.get('name')=='package' and job.get('status')=='completed'
            and job.get('conclusion')=='success' and job.get('head_sha')==build.sha
            and type(job.get('run_id')) is int and job['run_id']==int(build.run_id)
            and type(job.get('steps')) is list and len(job['steps'])<=32,'PRIVATE_ARTIFACT_SCOPE_REFUSED')
    order=[]
    for name in required_steps:
        matches=[step for step in job['steps'] if type(step) is dict and step.get('name')==name]
        require(len(matches)==1 and matches[0].get('status')=='completed' and matches[0].get('conclusion')=='success'
                and type(matches[0].get('number')) is int and matches[0]['number']>0,'PRIVATE_ARTIFACT_SCOPE_REFUSED')
        order.append(matches[0]['number'])
    require(order==sorted(set(order)),'PRIVATE_ARTIFACT_SCOPE_REFUSED')
    rows=listing.get('artifacts')
    require(type(rows) is list and len(rows)<=8 and type(listing.get('total_count')) is int
            and listing['total_count']==len(rows),'PRIVATE_ARTIFACT_SCOPE_REFUSED')
    selected=[row for row in rows if type(row) is dict and row.get('name')==build.artifact_name]
    require(len(selected)==1 and selected[0]==item,'PRIVATE_ARTIFACT_SCOPE_REFUSED')
    require(type(item.get('id')) is int and item['id']==int(build.artifact_id)
            and item.get('expired') is False and item.get('digest')=='sha256:'+build.archive_sha256
            and type(item.get('size_in_bytes')) is int and 0<item['size_in_bytes']<=ARCHIVE_LIMIT
            and item.get('workflow_run',{}).get('id')==int(build.run_id)
            and item['workflow_run'].get('head_sha')==build.sha,'PRIVATE_ARTIFACT_SCOPE_REFUSED')
    return item['size_in_bytes']


def storage_target(location):
    require(type(location) is str and 0<len(location)<=8192,'PRIVATE_DOWNLOAD_REFUSED')
    parsed=urlsplit(location)
    require(parsed.scheme=='https' and parsed.username is None and parsed.password is None
            and parsed.port in (None,443) and parsed.fragment==''
            and type(parsed.hostname) is str and re.fullmatch(r'productionresultssa[0-9]+\.blob\.core\.windows\.net',parsed.hostname)
            and parsed.path.startswith('/') and not any(c in location for c in '\r\n\0'),'PRIVATE_DOWNLOAD_REFUSED')
    return parsed.hostname,parsed.path+('?' + parsed.query if parsed.query else '')


def headers(response):
    rows=response.getheaders()
    require(len(rows)<=64 and sum(len(k)+len(v)+4 for k,v in rows)<=16384,'PRIVATE_DOWNLOAD_REFUSED')
    return rows


class HeaderReader:
    def __init__(self,file,sock,deadline):self.file,self.sock,self.deadline,self.total=file,sock,deadline,0
    def readline(self,limit=-1):
        raw=bytearray()
        while limit<0 or len(raw)<limit:
            left=self.deadline-time.monotonic();require(left>0,'PRIVATE_DOWNLOAD_DEADLINE')
            self.sock.settimeout(min(15,left))
            try:part=self.file.read1(1)
            except OSError:raise ActionsRefused('PRIVATE_DOWNLOAD_DEADLINE' if time.monotonic()>=self.deadline else 'PRIVATE_DOWNLOAD_REFUSED') from None
            if not part:break
            self.total+=len(part);require(self.total<=16384,'PRIVATE_DOWNLOAD_REFUSED')
            raw.extend(part)
            if part==b'\n':break
        return bytes(raw)
    def __getattr__(self,name):return getattr(self.file,name)


class HeaderResponse(http.client.HTTPResponse):
    def __init__(self,sock,*args,deadline,**kwargs):
        self._guard_socket,self._guard_deadline=sock,deadline
        super().__init__(sock,*args,**kwargs)
    def begin(self):
        original=self.fp
        self.fp=HeaderReader(original,self._guard_socket,self._guard_deadline)
        try:return super().begin()
        finally:self.fp=original


def download(build,token,destination,expected_size,deadline,connection=http.client.HTTPSConnection):
    require(type(expected_size) is int and 0<expected_size<=ARCHIVE_LIMIT,'PRIVATE_DOWNLOAD_REFUSED')
    require(type(build) is Build and type(token) is str and re.fullmatch('[!-~]{1,4096}',token),
            'ARTIFACT_READ_TOKEN_NOT_CONFIGURED')
    links=[];fd=None
    def connect(host):
        left=deadline-time.monotonic();require(left>0,'PRIVATE_DOWNLOAD_DEADLINE')
        result=connection(host,timeout=min(15,left),context=ssl.create_default_context())
        result.response_class=lambda sock,*args,**kwargs:HeaderResponse(sock,*args,deadline=deadline,**kwargs)
        links.append(result);return result
    try:
        api=connect('api.github.com')
        api.request('GET',SOURCE_API+'/actions/artifacts/'+build.artifact_id+'/zip',headers={
            'Authorization':'Bearer '+token,'Accept':'application/vnd.github+json','User-Agent':'jsm-clean-test-2760'})
        response=api.getresponse();rows=headers(response)
        locations=[v for k,v in rows if k.lower()=='location']
        require(response.status==302 and len(locations)==1,'PRIVATE_DOWNLOAD_REFUSED')
        host,path=storage_target(locations[0]);response.close()
        storage=connect(host)
        # Authorization is never forwarded to storage. No redirect/retry follows.
        storage.request('GET',path,headers={'User-Agent':'jsm-clean-test-2760','Accept':'application/zip'})
        body_socket=storage.sock
        response=storage.getresponse();rows=headers(response)
        lengths=[v for k,v in rows if k.lower()=='content-length']
        require(response.status==200 and len(lengths)==1 and re.fullmatch('[1-9][0-9]{0,10}',lengths[0])
                and int(lengths[0])==expected_size
                and not any(k.lower()=='transfer-encoding' or k.lower()=='content-encoding' and v.lower()!='identity' for k,v in rows),'PRIVATE_DOWNLOAD_REFUSED')
        fd=os.open(destination,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
        digest=sha256();total=0
        while total<expected_size:
            left=deadline-time.monotonic();require(left>0,'PRIVATE_DOWNLOAD_DEADLINE')
            if body_socket is not None:body_socket.settimeout(min(15,left))
            raw=response.read1(min(65536,expected_size+1-total))
            if not raw:break
            total+=len(raw);require(total<=expected_size,'PRIVATE_DOWNLOAD_REFUSED');digest.update(raw)
            offset=0
            while offset<len(raw):
                written=os.write(fd,raw[offset:]);require(written>0,'PRIVATE_DOWNLOAD_REFUSED');offset+=written
        require(time.monotonic()<deadline and total==expected_size and digest.hexdigest()==build.archive_sha256,'PRIVATE_DOWNLOAD_REFUSED')
    except Exception as error:
        if type(error) is ActionsRefused:raise
        raise ActionsRefused('PRIVATE_DOWNLOAD_REFUSED') from None
    finally:
        if fd is not None:os.close(fd)
        for link in links:
            try:link.close()
            except Exception:pass
