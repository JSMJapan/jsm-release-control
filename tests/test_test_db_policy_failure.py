"""Actual public getter/parser to DB receipt, entirely synthetic HTTP bytes."""
import http.client
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tests'))
import test_test_db_metadata_readonly as fixtures


class PolicyFailureTests(unittest.TestCase):
    def setUp(self):
        core=fixtures.ScopePolicyTests();core.setUp();self.core=core;self.m=core.m
        api,_=core.api();self.paths=[self.m.GH_REPO,self.m.GH_ENV,self.m.GH_ENV+'/deployment-branch-policies']
        self.rows=[api.get_json(path) for path in self.paths]

    def wire(self,index=0,status=403,headers=(),cleanup=None,status_override=...,header_override=...,request_failure_at=None):
        calls=[];closed=[];responses=[];connections=[];outer=self
        class Socket:
            def __init__(inner,data):inner.data=data
            def makefile(inner,*args):return io.BytesIO(inner.data)
            def settimeout(inner,value):outer.assertGreater(value,0);outer.assertLessEqual(value,10)
        class Connection:
            def __init__(inner,host,port,**kwargs):
                outer.assertEqual((host,port),('api.github.com',443));inner.sock=None;inner.number=len(connections)
                connections.append(inner)
            def request(inner,method,path,body,headers):
                outer.assertEqual(method,'GET');outer.assertIsNone(body)
                outer.assertNotIn('Authorization',headers);outer.assertNotIn('Cookie',headers)
                if inner.number==request_failure_at:
                    calls.append(path);raise OSError('PRIVATE_TRANSPORT')
                calls.append(path);outer.assertEqual(path,outer.paths[inner.number%3])
                bad=inner.number==index;code=status if bad else 200
                payload=b'PRIVATE_BODY_COOKIE' if bad and code!=200 else json.dumps(outer.rows[inner.number%3]).encode()
                extra=headers_fixture if bad else ()
                raw=('HTTP/1.1 '+str(code)+' PRIVATE_STATUS_TEXT\r\nContent-Type: application/json\r\nContent-Length: '+str(len(payload))+'\r\nConnection: close\r\n').encode()
                raw+=b''.join(name.encode()+b': '+value.encode('latin1')+b'\r\n' for name,value in extra)+b'\r\n'+payload
                inner.sock=Socket(raw)
            def getresponse(inner):
                response=http.client.HTTPResponse(inner.sock,method='GET');response.begin();responses.append(response)
                if status_override is not ...:response.status=status_override
                if header_override is not ...:response.headers=header_override
                original=response.close;once=[False]
                def close():
                    closed.append(('response',inner.number));original()
                    if cleanup and cleanup[0]=='response' and not once[0]:once[0]=True;raise cleanup[1]
                response.close=close
                if response.status!=200:
                    def forbidden(*args):raise AssertionError('non200 body must not be read')
                    response.read1=forbidden
                return response
            def close(inner):
                closed.append(('connection',inner.number))
                if cleanup and cleanup[0]=='connection':raise cleanup[1]
        headers_fixture=headers
        return Connection,calls,closed,responses

    def run_main(self,factory,env=None,api=None):
        out=io.StringIO();err=io.StringIO();env=self.core.context() if env is None else env
        with patch.object(http.client,'HTTPSConnection',factory), \
                patch.object(self.m,'_bounded',side_effect=AssertionError('PRIVATE_SSH')), \
                patch.object(self.m,'private_file',side_effect=AssertionError('PRIVATE_KEY')), \
                patch.object(self.m.sys,'argv',[str(fixtures.SCRIPT)]), \
                patch.object(self.m.os,'environ',env),patch('sys.stdout',out),patch('sys.stderr',err):
            if api is None:code=self.m.main()
            else:
                with patch.object(self.m,'TestPolicyApi',return_value=api):code=self.m.main()
        self.assertEqual(code,1);self.assertEqual(err.getvalue(),'');self.assertNotIn('PRIVATE',out.getvalue())
        value=json.loads(out.getvalue());self.assertEqual(value['status'],'BLOCKED')
        self.assertEqual(value['ssh'],'NOT_ATTEMPTED');self.assertEqual(value['sql'],'NOT_ATTEMPTED')
        self.assertEqual(value['database_credentials'],'NOT_ACCESSED');self.assertIsNone(value['os_observation'])
        return value

    def test_three_endpoints_and_closed_statuses_keep_original_trace_and_refusal(self):
        for index,endpoint in enumerate(('REPOSITORY','ENVIRONMENT','BRANCHES')):
            for status in (301,302,303,307,308,401,403,404,429,500,502,503,504,418):
                with self.subTest(endpoint=endpoint,status=status):
                    factory,calls,closed,_=self.wire(index,status)
                    value=self.run_main(factory)
                    self.assertEqual(value['reason'],'GITHUB_GET_STATUS_REFUSED')
                    self.assertIs(value['protected_policy_verified'],False)
                    self.assertEqual(value.get('policy_failure'),dict(endpoint=endpoint,
                        http_status=str(status) if status!=418 else 'OTHER',rate_category='UNDETERMINED'))
                    self.assertEqual(calls,self.paths[:index+1])
                    self.assertEqual(closed,[row for i in range(index+1) for row in (('response',i),('connection',i))])

    def test_rate_headers_are_unique_bounded_and_only_observed_hints(self):
        remaining='X-RateLimit-Remaining';retry='Retry-After'
        cases=[(403,[(remaining,'0')],'RATE_REMAINING_ZERO'),
            (429,[(remaining,'0'),(retry,'12')],'RATE_REMAINING_ZERO'),
            (403,[(remaining,'9'),(retry,'12')],'RETRY_AFTER_HINT'),
            (429,[(retry,'0')],'RETRY_AFTER_HINT'),(403,[],'UNDETERMINED'),
            # HTTPResponse removes valid leading field OWS before get_all().
            (403,[(remaining,' 0')],'RATE_REMAINING_ZERO'),
            (500,[(remaining,'0'),(retry,'12')],'UNDETERMINED'),
            (403,[(remaining,'0'),(remaining,'0'),(retry,'12')],'UNDETERMINED'),
            (403,[(remaining,'0'),(retry,'12'),(retry,'12')],'UNDETERMINED'),
            (403,[(remaining,'0'),(retry,'PRIVATE')],'UNDETERMINED')]
        for raw in ('','00','-1','+0','0, 0','0'*80,'\xff','0\r\n\tPRIVATE'):
            cases.append((403,[(remaining,raw),(retry,'12')],'UNDETERMINED'))
        for status,headers,expected in cases:
            with self.subTest(status=status,header_case=len(headers),expected=expected):
                factory,_,_,_=self.wire(1,status,headers)
                value=self.run_main(factory)
                self.assertEqual(value.get('policy_failure'),dict(endpoint='ENVIRONMENT',http_status=str(status),rate_category=expected))

    def test_cleanup_replacements_and_nonstatus_errors_cannot_reuse_evidence(self):
        for where in ('response','connection'):
            for error in (RuntimeError('PRIVATE','SECOND'),self.m.Refused('GITHUB_GET_STATUS_REFUSED')):
                error._github_policy_failure=dict(endpoint='REPOSITORY',http_status='403',rate_category='RATE_REMAINING_ZERO')
                factory,_,closed,_=self.wire(cleanup=(where,error))
                value=self.run_main(factory)
                self.assertIn('policy_failure',value);self.assertIsNone(value['policy_failure'])
                self.assertEqual(closed,[('response',0)] if where=='response' else [('response',0),('connection',0)])
        for reason in ('GITHUB_READ_DEADLINE','GITHUB_TRANSPORT_OR_SCHEMA_REFUSED','PRIVATE'):
            error=self.m.Refused(reason);error._github_policy_failure=dict(endpoint='REPOSITORY',http_status='403',rate_category='RATE_REMAINING_ZERO')
            class Api:
                def get_json(inner,path):raise error
            factory,_,_,_=self.wire();value=self.run_main(factory,api=Api())
            self.assertIn('policy_failure',value);self.assertIsNone(value['policy_failure'])

    def test_success_and_stale_context_leave_no_policy_failure_or_extra_get(self):
        factory,calls,_,_=self.wire(index=-1)
        value=self.run_main(factory)
        self.assertEqual(calls,self.paths);self.assertTrue(value['protected_policy_verified'])
        self.assertEqual(value['reason'],'TEST_SSH_KEY_NOT_CONFIGURED')
        self.assertIn('policy_failure',value);self.assertIsNone(value['policy_failure'])
        for key,new in [('GITHUB_RUN_ATTEMPT','2'),('GITHUB_WORKFLOW_SHA','b'*40),('GITHUB_ACTOR','PRIVATE')]:
            factory,calls,_,_=self.wire();env=self.core.context();env[key]=new
            value=self.run_main(factory,env)
            self.assertEqual(calls,[]);self.assertIn('policy_failure',value);self.assertIsNone(value['policy_failure'])

    def test_shared_getter_and_existing_stage_wrapper_keep_legacy_type_args_and_cleanup(self):
        import test_api_readonly_access as access
        for staged in (False,True):
            factory,calls,closed,_=self.wire()
            with patch.object(http.client,'HTTPSConnection',factory):
                api=access.TestPolicyApi()
                with self.assertRaises(self.m.Refused) as caught:
                    if staged:access._at_stage('policy_repository',api.get_json,self.paths[0])
                    else:api.get_json(self.paths[0])
            self.assertEqual(caught.exception.args,('GITHUB_GET_STATUS_REFUSED',))
            self.assertIs(type(caught.exception),access._ProbeFailure if staged else self.m.Refused)
            if staged:self.assertEqual(caught.exception.failure_stage,'policy_repository')
            self.assertEqual(calls,self.paths[:1]);self.assertEqual(closed,[('response',0),('connection',0)])

    def test_unusual_status_and_malformed_header_containers_stay_closed(self):
        for status,expected in [(None,'UNKNOWN'),(True,'UNKNOWN'),('PRIVATE','UNKNOWN'),
                (403.0,'UNKNOWN'),(999,'OTHER'),(10**5000,'OTHER')]:
            with self.subTest(status_type=type(status).__name__):
                factory,_,_,_=self.wire(status_override=status)
                value=self.run_main(factory)
                self.assertEqual(value['reason'],'GITHUB_GET_STATUS_REFUSED')
                self.assertEqual(value.get('policy_failure'),dict(endpoint='REPOSITORY',http_status=expected,rate_category='UNDETERMINED'))
        class Headers:
            def __init__(inner,value):inner.value=value
            def get_all(inner,name,default):
                if isinstance(inner.value,Exception):raise inner.value
                return inner.value if name=='X-RateLimit-Remaining' else ['5']
        for rows in (None,('0',),'0',[None],[0],[True],['0','0'],[b'0'],[{}],RuntimeError('PRIVATE')):
            with self.subTest(rows_type=type(rows).__name__):
                factory,_,_,_=self.wire(header_override=Headers(rows))
                value=self.run_main(factory)
                self.assertEqual(value.get('policy_failure'),dict(endpoint='REPOSITORY',http_status='403',rate_category='UNDETERMINED'))

    def test_private_multiarg_cross_endpoint_and_forged_context_are_not_projected(self):
        good=dict(endpoint='REPOSITORY',http_status='403',rate_category='RATE_REMAINING_ZERO')
        bad=[None,[],dict(good,raw_url='PRIVATE'),dict(good,endpoint='ENVIRONMENT'),
            dict(good,endpoint=['REPOSITORY']),dict(good,http_status=403),dict(good,http_status=True),
            dict(good,http_status='PRIVATE'),dict(good,rate_category='PRIVATE'),
            dict(good,http_status='500'),dict(good,http_status='UNKNOWN'),dict(good,rate_category=['UNDETERMINED'])]
        for context in bad:
            error=self.m.Refused('GITHUB_GET_STATUS_REFUSED');error._github_policy_failure=context
            class Api:
                def get_json(inner,path):raise error
            factory,_,_,_=self.wire();value=self.run_main(factory,api=Api())
            self.assertIn('policy_failure',value);self.assertIsNone(value['policy_failure'])
        for error in (RuntimeError('GITHUB_GET_STATUS_REFUSED'),self.m.Refused('PRIVATE')):
            error._github_policy_failure=good
            factory,_,_,_=self.wire();value=self.run_main(factory,api=Api())
            self.assertIsNone(value['policy_failure'])
        error=self.m.Refused('PRIVATE');error.args=('GITHUB_GET_STATUS_REFUSED','PRIVATE');error._github_policy_failure=good
        factory,_,_,_=self.wire();self.assertIsNone(self.run_main(factory,api=Api())['policy_failure'])

    def test_reused_api_and_new_main_progress_do_not_retain_old_failure(self):
        api=self.m.TestPolicyApi();deadline=api.deadline
        factory,calls,_,_=self.wire(request_failure_at=1)
        first=self.run_main(factory,api=api);second=self.run_main(factory,api=api)
        self.assertIn('policy_failure',first)
        self.assertEqual(first['policy_failure']['endpoint'],'REPOSITORY')
        self.assertEqual(second['reason'],'GITHUB_TRANSPORT_OR_SCHEMA_REFUSED');self.assertIsNone(second['policy_failure'])
        self.assertEqual(calls,[self.paths[0],self.paths[0]]);self.assertEqual(api.deadline,deadline)
        factory,calls,_,_=self.wire(index=-1)
        third=self.run_main(factory,api=api);self.assertIsNone(third['policy_failure'])
        self.assertEqual(calls,self.paths);self.assertEqual(api.deadline,deadline)

    def test_cleanup_exception_identity_args_and_stop_order_are_unchanged(self):
        import test_api_readonly_access as access
        for where in ('response','connection'):
            for error in (RuntimeError('PRIVATE','SECOND'),self.m.Refused('GITHUB_GET_STATUS_REFUSED')):
                error._github_policy_failure=dict(endpoint='REPOSITORY',http_status='403',rate_category='RATE_REMAINING_ZERO')
                arguments=error.args;factory,_,closed,_=self.wire(cleanup=(where,error))
                with patch.object(http.client,'HTTPSConnection',factory):
                    with self.assertRaises(type(error)) as caught:access.TestPolicyApi().get_json(self.paths[0])
                self.assertIs(caught.exception,error);self.assertEqual(error.args,arguments)
                self.assertIsNone(error._github_policy_failure)
                self.assertEqual(closed,[('response',0)] if where=='response' else [('response',0),('connection',0)])


if __name__=='__main__':unittest.main()
