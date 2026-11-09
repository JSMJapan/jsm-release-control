import contextlib
import importlib.util
import io
import json
import pathlib
import sys
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts/hostinger_preflight.py'


class PreflightTest(unittest.TestCase):
    def setUp(self):
        self.assertTrue(SCRIPT.is_file(), 'Missing read-only Hostinger diagnostic')
        spec = importlib.util.spec_from_file_location('hostinger_preflight', SCRIPT)
        self.module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = self.module
        spec.loader.exec_module(self.module)

    def context(self):
        return dict(GITHUB_REPOSITORY='JSMJapan/jsm-release-control', GITHUB_ACTOR='JSMJapan',
                    GITHUB_TRIGGERING_ACTOR='JSMJapan', GITHUB_REF='refs/heads/main',
                    GITHUB_EVENT_NAME='workflow_dispatch', GITHUB_RUN_ATTEMPT='1',
                    GITHUB_SERVER_URL='https://github.com', GITHUB_API_URL='https://api.github.com',
                    GITHUB_SHA='a' * 40, GITHUB_WORKFLOW_SHA='a' * 40, GITHUB_RUN_ID='123456789',
                    GITHUB_WORKFLOW_REF='JSMJapan/jsm-release-control/.github/workflows/hostinger-readonly-preflight.yml@refs/heads/main',
                    HOSTINGER_API_TOKEN='PRIVATE_TOKEN_FIXTURE')

    def fixtures(self, vm_id=987654321):
        vm = dict(id=vm_id, hostname='srv1687281.hstgr.cloud', state='running',
                  ipv4=[dict(id=123, address='187.77.118.50', ptr='PRIVATE_PTR')], subscription_id='PRIVATE_BILLING')
        env = dict(can_admins_bypass=False, protection_rules=[dict(type='required_reviewers', prevent_self_review=False,
                   reviewers=[dict(type='User', reviewer=dict(login='JSMJapan'))])],
                   deployment_branch_policy=dict(protected_branches=False, custom_branch_policies=True))
        return [dict(full_name='JSMJapan/jsm-release-control', private=False), env,
                dict(total_count=1, branch_policies=[dict(name='main', type='branch')]),
                [dict(id=42, hostname='OTHER_ACCOUNT_VM', ipv4=[dict(address='127.0.0.8')]), vm], vm,
                [dict(key='PRIVATE_RAW_ROOT_KEY', type='ssh-ed25519', data='PRIVATE_DATA', name='PRIVATE_NAME')]]

    def fake_client(self, fixtures):
        calls = []
        class Client:
            def get_json(inner, host, path, token=None):
                calls.append((host, path, token))
                return fixtures[len(calls) - 1]
        return Client(), calls

    def test_unique_ip_hostname_binds_actual_api_id_without_deriving_srv_digits_and_redacts_everything_else(self):
        client, calls = self.fake_client(self.fixtures())
        result = self.module.collect(client, self.context())
        self.assertEqual(result['vm_id'], 987654321)
        self.assertEqual(result['ip'], '187.77.118.50')
        self.assertEqual(result['root_ssh_key_count'], 1)
        self.assertEqual(result['ssh_options_preservation'], 'UNVERIFIED')
        self.assertEqual(result['provider_mutations'], 'NOT_PERFORMED')
        self.assertEqual([path for host, path, token in calls if host == 'developers.hostinger.com'],
                         ['/api/vps/v1/virtual-machines', '/api/vps/v1/virtual-machines/987654321',
                          '/api/vps/v1/virtual-machines/987654321/ssh-keys'])
        self.assertTrue(all(token is None for host, path, token in calls if host == 'api.github.com'))
        self.assertTrue(all(token == 'PRIVATE_TOKEN_FIXTURE' for host, path, token in calls if host == 'developers.hostinger.com'))
        output = json.dumps(result)
        for secret in ('PRIVATE_TOKEN', 'PRIVATE_PTR', 'PRIVATE_BILLING', 'PRIVATE_RAW_ROOT_KEY', 'PRIVATE_NAME', 'OTHER_ACCOUNT_VM'):
            self.assertNotIn(secret, output)

    def test_observed_provider_hostname_is_the_only_pin_and_former_friendly_name_is_rejected_at_both_stages(self):
        client, calls = self.fake_client(self.fixtures())
        result = self.module.collect(client, self.context())
        self.assertEqual(result['hostname'], 'srv1687281.hstgr.cloud')
        self.assertEqual(result['vm_id'], 987654321)
        for stage in ('list_candidate', 'detail'):
            fixtures = self.fixtures()
            if stage == 'list_candidate':
                fixtures[3][1] = dict(fixtures[3][1], hostname='jsmjapan-prod-01')
            else:
                fixtures[4] = dict(fixtures[4], hostname='jsmjapan-prod-01')
            client, calls = self.fake_client(fixtures)
            with self.assertRaises(self.module.Refused) as failure:
                self.module.collect(client, self.context())
            self.assertEqual(str(failure.exception), 'FIXED_RESOURCE_BINDING_NOT_VERIFIED')
            self.assertEqual(failure.exception.error_evidence['stage'], stage)
            self.assertIs(failure.exception.error_evidence['hostname_expected'], False)
            self.assertIs(failure.exception.error_evidence['hostname_matches_exact_known_resource_fqdn'], False)
            provider = [path for host, path, token in calls if host == 'developers.hostinger.com']
            self.assertEqual(len(provider), 1 if stage == 'list_candidate' else 2)
            self.assertFalse(any(path.endswith('/ssh-keys') for path in provider))

    def test_unknown_duplicate_or_rebound_resource_never_reaches_ssh_key_endpoint(self):
        for case in ('hostname', 'duplicate', 'rebound', 'bool_id'):
            fixtures = self.fixtures()
            if case == 'hostname': fixtures[3][1]['hostname'] = 'wrong-host'
            if case == 'duplicate': fixtures[3].append(dict(fixtures[3][1]))
            if case == 'rebound': fixtures[4] = dict(fixtures[4], id=123)
            if case == 'bool_id': fixtures[3][1]['id'] = True
            client, calls = self.fake_client(fixtures)
            with self.assertRaises(self.module.Refused):
                self.module.collect(client, self.context())
            self.assertFalse(any(path.endswith('/ssh-keys') for host, path, token in calls))

    def test_unprotected_wrong_reviewer_branch_bypass_private_or_missing_token_never_contacts_hostinger(self):
        for case in ('private', 'reviewer', 'branch', 'bypass', 'missing_token'):
            fixtures = self.fixtures()
            env = self.context()
            if case == 'private': fixtures[0]['private'] = True
            if case == 'reviewer': fixtures[1]['protection_rules'] = []
            if case == 'branch': fixtures[2]['branch_policies'][0]['name'] = '*'
            if case == 'bypass': fixtures[1]['can_admins_bypass'] = True
            if case == 'missing_token': env.pop('HOSTINGER_API_TOKEN')
            client, calls = self.fake_client(fixtures)
            with self.assertRaises(self.module.Refused):
                self.module.collect(client, env)
            self.assertFalse(any(host == 'developers.hostinger.com' for host, path, token in calls))

    def test_owner_manual_main_first_attempt_guard_refuses_before_any_network(self):
        for field, value in (('GITHUB_REPOSITORY', 'JSMJapan/jsm-storefront'), ('GITHUB_ACTOR', 'other'),
                             ('GITHUB_REF', 'refs/heads/other'), ('GITHUB_EVENT_NAME', 'push'),
                             ('GITHUB_RUN_ATTEMPT', '2')):
            env = self.context(); env[field] = value
            client, calls = self.fake_client(self.fixtures())
            with self.assertRaises(self.module.Refused): self.module.collect(client, env)
            self.assertEqual(calls, [])

    def test_transport_allows_only_fixed_https_get_paths_and_never_sends_provider_token_to_other_host(self):
        api = self.module.Api()
        for host, path, token in (('evil.example', '/', 'PRIVATE'), ('api.github.com', '/repos/evil/x', None),
                                  ('developers.hostinger.com', '/api/vps/v1/virtual-machines/1/restart', 'PRIVATE'),
                                  ('developers.hostinger.com', '/api/vps/v1/virtual-machines?anything=1', 'PRIVATE'),
                                  ('api.github.com', '/repos/JSMJapan/jsm-release-control', 'PRIVATE')):
            with self.assertRaises(self.module.Refused), patch.object(self.module.http.client, 'HTTPSConnection') as connect:
                api.get_json(host, path, token)
            connect.assert_not_called()

    def test_http_redirect_oversized_non_json_encoding_and_transport_exceptions_are_generic(self):
        class Response:
            status = 200
            headers = {'Content-Type': 'application/json'}
            body = b'[]'
            def getheader(inner, name): return inner.headers.get(name)
            def read1(inner, size):
                data = inner.body[:size]; inner.body = inner.body[size:]; return data
            def close(inner): pass
        class Connection:
            sock = None
            response = Response()
            def request(inner, method, path, body=None, headers=None):
                self.assertEqual(method, 'GET')
                self.assertIsNone(body)
                self.assertNotIn('Cookie', headers)
                self.assertEqual(headers.get('Authorization'), 'Bearer PRIVATE_TOKEN_FIXTURE')
            def getresponse(inner): return inner.response
            def close(inner): pass
        for case in ('ok', 'redirect', 'length', 'type', 'encoding', 'body', 'exception'):
            connection = Connection(); connection.response = Response()
            connection.response.headers = dict(Response.headers)
            if case == 'redirect': connection.response.status = 302
            if case == 'length': connection.response.headers['Content-Length'] = '999999999'
            if case == 'type': connection.response.headers['Content-Type'] = 'text/html'
            if case == 'encoding': connection.response.headers['Content-Encoding'] = 'gzip'
            if case == 'body': connection.response.body = b'x' * (self.module.MAX_BYTES + 1)
            with patch.object(self.module.http.client, 'HTTPSConnection', return_value=connection) as connect:
                if case == 'exception': connect.side_effect = RuntimeError('PRIVATE_TOKEN_FIXTURE raw private body')
                api = self.module.Api()
                if case == 'ok': self.assertEqual(api.get_json('developers.hostinger.com', '/api/vps/v1/virtual-machines', 'PRIVATE_TOKEN_FIXTURE'), [])
                else:
                    with self.assertRaises(self.module.Refused) as failure:
                        api.get_json('developers.hostinger.com', '/api/vps/v1/virtual-machines', 'PRIVATE_TOKEN_FIXTURE')
                    self.assertNotIn('PRIVATE', str(failure.exception))

    def test_slow_stream_stops_at_overall_deadline_without_retry_or_outputting_body(self):
        class Response:
            status = 200
            def getheader(inner, name): return 'application/json' if name == 'Content-Type' else None
            def read1(inner, size): return b'PRIVATE_PARTIAL_BODY'
            def close(inner): pass
        class Connection:
            sock = None
            def request(inner, method, path, body=None, headers=None): self.assertEqual(method, 'GET')
            def getresponse(inner): return Response()
            def close(inner): pass
        api = self.module.Api(); api.deadline = 1
        with patch.object(self.module.time, 'monotonic', side_effect=[0, 0, 2]), \
                patch.object(self.module.http.client, 'HTTPSConnection', return_value=Connection()) as connect:
            with self.assertRaisesRegex(self.module.Refused, '^OVERALL_DEADLINE$'):
                api.get_json('developers.hostinger.com', '/api/vps/v1/virtual-machines', 'PRIVATE_TOKEN_FIXTURE')
            self.assertEqual(connect.call_count, 1)

    def test_main_failure_receipt_never_includes_raw_exception_token_or_provider_body(self):
        class Broken:
            def get_json(inner, *args): raise RuntimeError('PRIVATE_TOKEN_FIXTURE PRIVATE_RAW_ROOT_KEY PRIVATE_BODY')
        output = io.StringIO()
        with patch.object(self.module, 'Api', return_value=Broken()), patch.dict(self.module.os.environ, self.context(), clear=True), \
                patch.object(self.module.os.sys, 'argv', ['preflight.py']), \
                patch.object(self.module.signal, 'signal'), patch.object(self.module.signal, 'setitimer'), \
                contextlib.redirect_stdout(output):
            self.assertEqual(self.module.main(), 1)
        receipt = json.loads(output.getvalue())
        self.assertEqual(receipt['status'], 'BLOCKED')
        self.assertEqual(receipt['reason'], 'INTERNAL_SCHEMA_OR_TRANSPORT_REJECTED')
        self.assertNotIn('PRIVATE', output.getvalue())

    def test_binding_failure_identifies_list_or_detail_with_closed_boolean_witness_and_no_extra_requests(self):
        expected = dict(stage='list_candidate', vm_object=True, id_valid=True, ipv4_array=True,
                        expected_ip_count='one', hostname_expected=False,
                        hostname_matches_exact_known_resource_fqdn=False, expected_id_matches=True)
        for case in ('former_friendly_name', 'arbitrary_hostname', 'invalid_id', 'duplicate_ip',
                     'detail_rebound', 'detail_ip', 'detail_schema'):
            with self.subTest(case=case):
                fixtures = self.fixtures()
                witness = dict(expected)
                if case == 'former_friendly_name': fixtures[3][1]['hostname'] = 'jsmjapan-prod-01'
                if case == 'arbitrary_hostname': fixtures[3][1]['hostname'] = 'PRIVATE_HOSTNAME_TOKEN_ECHO'
                if case == 'invalid_id':
                    fixtures[3][1]['id'] = True
                    witness.update(id_valid=False, hostname_expected=True, hostname_matches_exact_known_resource_fqdn=True)
                if case == 'duplicate_ip':
                    fixtures[3][1]['ipv4'].append(dict(address='187.77.118.50'))
                    witness.update(expected_ip_count='multiple', hostname_expected=True, hostname_matches_exact_known_resource_fqdn=True)
                if case.startswith('detail_'):
                    witness.update(stage='detail', hostname_expected=True, hostname_matches_exact_known_resource_fqdn=True)
                if case == 'detail_rebound':
                    fixtures[4] = dict(fixtures[4], id=123)
                    witness['expected_id_matches'] = False
                if case == 'detail_ip':
                    fixtures[4] = dict(fixtures[4], ipv4=[dict(address='PRIVATE_OTHER_IP')])
                    witness['expected_ip_count'] = 'zero'
                if case == 'detail_schema':
                    fixtures[4] = None
                    witness.update(vm_object=False, id_valid=False, ipv4_array=False,
                                   expected_ip_count='not_array', hostname_expected=False,
                                   hostname_matches_exact_known_resource_fqdn=False, expected_id_matches=False)
                client, calls = self.fake_client(fixtures)
                with self.assertRaises(self.module.Refused) as failure:
                    self.module.collect(client, self.context())
                self.assertEqual(str(failure.exception), 'FIXED_RESOURCE_BINDING_NOT_VERIFIED')
                self.assertEqual(getattr(failure.exception, 'error_evidence', None), witness)
                provider = [path for host, path, token in calls if host == 'developers.hostinger.com']
                self.assertEqual(len(provider), 2 if case.startswith('detail_') else 1)
                self.assertFalse(any(path.endswith('/ssh-keys') for path in provider))

    def test_main_binding_failure_projects_only_fixed_witness_not_raw_hostname_or_account_fields(self):
        fixtures = self.fixtures()
        fixtures[3][1]['hostname'] = 'PRIVATE_ACCOUNT_HOSTNAME'
        client, calls = self.fake_client(fixtures)
        output = io.StringIO()
        with patch.object(self.module, 'Api', return_value=client), patch.dict(self.module.os.environ, self.context(), clear=True), \
                patch.object(self.module.os.sys, 'argv', ['preflight.py']), \
                patch.object(self.module.signal, 'signal'), patch.object(self.module.signal, 'setitimer'), \
                contextlib.redirect_stdout(output):
            self.assertEqual(self.module.main(), 1)
        receipt = json.loads(output.getvalue())
        self.assertEqual(receipt['status'], 'BLOCKED')
        self.assertEqual(receipt['reason'], 'FIXED_RESOURCE_BINDING_NOT_VERIFIED')
        self.assertEqual(receipt.get('error_evidence', {}).get('stage'), 'list_candidate')
        self.assertIs(receipt['error_evidence']['hostname_expected'], False)
        self.assertEqual(receipt['provider_mutations'], 'NOT_PERFORMED')
        for marker in ('PRIVATE', 'OTHER_ACCOUNT_VM', 'srv1687281.hstgr.cloud'):
            self.assertNotIn(marker, output.getvalue())
        self.assertFalse(any(path.endswith('/ssh-keys') for host, path, token in calls))

    def test_failure_witness_rejects_extra_fields_non_boolean_values_and_unknown_stage(self):
        valid = dict(stage='detail', vm_object=True, id_valid=True, ipv4_array=True,
                     expected_ip_count='one', hostname_expected=False,
                     hostname_matches_exact_known_resource_fqdn=False, expected_id_matches=True)
        for changed in (dict(valid, raw_hostname='PRIVATE_HOSTNAME'), dict(valid, hostname_expected='PRIVATE_HOSTNAME'),
                        dict(valid, stage='PRIVATE_STAGE'), dict(valid, expected_ip_count=987654321),
                        dict(valid, id_valid=1)):
            error = self.module.Refused('FIXED_RESOURCE_BINDING_NOT_VERIFIED', error_evidence=changed)
            self.assertIsNone(error.error_evidence)


if __name__ == '__main__': unittest.main()
