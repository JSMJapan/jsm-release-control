#!/usr/bin/env python3
"""Fixed GET-only Hostinger inventory probe; no shell, keys, access or deployment.

Public inventory: this file, its offline test and the fixed manual workflow only.
Official API base/auth: https://docs.hostinger.com/api-reference/overview
Official schemas: hostinger/api-python-sdk@a940165a2cdaf0e9a3de163e3fbc06f742d3622f
Hostinger tokens inherit creator permissions; GET-only is enforced by this code,
not a claim that the token itself has a documented read-only scope.
"""
import datetime
import http.client
import json
import os
import re
import signal
import ssl
import time

REPO = 'JSMJapan/jsm-release-control'
ENVIRONMENT = 'apache-parity-bootstrap'
GITHUB = 'api.github.com'
PROVIDER = 'developers.hostinger.com'
GH_REPO = '/repos/' + REPO
GH_ENV = GH_REPO + '/environments/' + ENVIRONMENT
GH_PATHS = {GH_REPO, GH_ENV, GH_ENV + '/deployment-branch-policies'}
VM_PATH = '/api/vps/v1/virtual-machines'
EXPECTED_IP = '187.77.118.50'
EXPECTED_HOSTNAME = 'jsmjapan-prod-01'
MAX_BYTES = 256 * 1024
DEADLINE_SECONDS = 45


class Refused(Exception):
    """Fixed public codes only; never provider response or exception text."""


class Api:
    def __init__(self):
        self.deadline = time.monotonic() + DEADLINE_SECONDS

    def remaining(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise Refused('OVERALL_DEADLINE')
        return min(10, remaining)

    def get_json(self, host, path, token=None):
        public = host == GITHUB and path in GH_PATHS and token is None
        provider = (host == PROVIDER and isinstance(path, str)
                    and re.fullmatch(re.escape(VM_PATH) + r'(?:/[1-9][0-9]{0,14}(?:/ssh-keys)?)?', path)
                    and isinstance(token, str) and re.fullmatch(r'[!-~]{1,4096}', token))
        if not (public or provider):
            raise Refused('FIXED_GET_SCOPE_REQUIRED')
        connection = response = None
        try:
            connection = http.client.HTTPSConnection(host, 443, timeout=self.remaining(), context=ssl.create_default_context())
            headers = {'Accept': 'application/json', 'Content-Type': 'application/json',
                       'Accept-Encoding': 'identity', 'User-Agent': 'jsm-hostinger-readonly-1568', 'Connection': 'close'}
            if public:
                headers['X-GitHub-Api-Version'] = '2022-11-28'
            else:
                headers['Authorization'] = 'Bearer ' + token
            connection.request('GET', path, body=None, headers=headers)
            response = connection.getresponse()
            if response.status != 200:
                raise Refused('HTTP_STATUS_REJECTED_' + str(response.status) if response.status in
                              (301, 302, 303, 307, 308, 401, 403, 404, 429, 500, 502, 503, 504) else 'HTTP_STATUS_REJECTED')
            if (response.getheader('Content-Type') or '').split(';')[0].strip().lower() != 'application/json':
                raise Refused('JSON_CONTENT_TYPE_REQUIRED')
            if (response.getheader('Content-Encoding') or 'identity').lower() != 'identity':
                raise Refused('ENCODED_RESPONSE_REFUSED')
            length = response.getheader('Content-Length')
            if length is not None and (not re.fullmatch('[0-9]+', length) or int(length) > MAX_BYTES):
                raise Refused('RESPONSE_TOO_LARGE_OR_LENGTH_INVALID')
            raw = bytearray()
            while True:
                if connection.sock is not None:
                    connection.sock.settimeout(self.remaining())
                self.remaining()
                block = response.read1(min(16384, MAX_BYTES + 1 - len(raw)))
                raw.extend(block)
                if len(raw) > MAX_BYTES:
                    raise Refused('RESPONSE_TOO_LARGE_OR_LENGTH_INVALID')
                if not block:
                    break
            return json.loads(raw.decode('utf-8'))
        except Refused:
            raise
        except Exception:
            raise Refused('HTTPS_TRANSPORT_OR_JSON_REJECTED') from None
        finally:
            if response is not None:
                response.close()
            if connection is not None:
                connection.close()


def context_ready(env):
    expected = dict(GITHUB_REPOSITORY=REPO, GITHUB_ACTOR='JSMJapan', GITHUB_TRIGGERING_ACTOR='JSMJapan',
                    GITHUB_REF='refs/heads/main', GITHUB_EVENT_NAME='workflow_dispatch', GITHUB_RUN_ATTEMPT='1',
                    GITHUB_SERVER_URL='https://github.com', GITHUB_API_URL='https://api.github.com',
                    GITHUB_WORKFLOW_REF=REPO + '/.github/workflows/hostinger-readonly-preflight.yml@refs/heads/main')
    if (any(env.get(name) != value for name, value in expected.items())
            or not re.fullmatch('[0-9a-f]{40}', env.get('GITHUB_SHA', ''))
            or env.get('GITHUB_WORKFLOW_SHA') != env.get('GITHUB_SHA')
            or not re.fullmatch('[0-9]{1,15}', env.get('GITHUB_RUN_ID', ''))):
        raise Refused('PUBLIC_CONTROL_REPO_OWNER_MANUAL_MAIN_FIRST_ATTEMPT_REQUIRED')


def policy_ready(repo, environment, branches):
    if not isinstance(repo, dict) or repo.get('full_name') != REPO or repo.get('private') is not False:
        raise Refused('PUBLIC_CONTROL_REPOSITORY_REQUIRED')
    if not isinstance(environment, dict) or not isinstance(branches, dict):
        raise Refused('PROTECTED_ENVIRONMENT_NOT_VERIFIED')
    rules = [rule for rule in environment.get('protection_rules', []) if rule.get('type') == 'required_reviewers']
    reviewer = rules[0] if len(rules) == 1 else {}
    reviewers = reviewer.get('reviewers', [])
    bindings = branches.get('branch_policies', [])
    if (environment.get('can_admins_bypass') is not False or reviewer.get('prevent_self_review') is not False
            or len(reviewers) != 1 or reviewers[0].get('type') != 'User'
            or reviewers[0].get('reviewer', {}).get('login') != 'JSMJapan'
            or environment.get('deployment_branch_policy') != dict(protected_branches=False, custom_branch_policies=True)
            or branches.get('total_count') != 1 or len(bindings) != 1
            or bindings[0].get('name') != 'main' or bindings[0].get('type') != 'branch'):
        raise Refused('PROTECTED_OWNER_MAIN_ENVIRONMENT_REQUIRED')


def bound_vm(vm, expected_id=None):
    if (not isinstance(vm, dict) or type(vm.get('id')) is not int or not 0 < vm['id'] < 10 ** 15
            or vm.get('hostname') != EXPECTED_HOSTNAME
            or not isinstance(vm.get('ipv4'), list)
            or sum(isinstance(ip, dict) and ip.get('address') == EXPECTED_IP for ip in vm['ipv4']) != 1
            or (expected_id is not None and vm['id'] != expected_id)):
        raise Refused('FIXED_RESOURCE_BINDING_NOT_VERIFIED')
    return vm['id']


def collect(api, env):
    context_ready(env)  # No network, token or provider access before invocation scope.
    repo = api.get_json(GITHUB, GH_REPO)
    if not isinstance(repo, dict) or repo.get('private') is not False or repo.get('full_name') != REPO:
        raise Refused('PUBLIC_CONTROL_REPOSITORY_REQUIRED')
    environment = api.get_json(GITHUB, GH_ENV)
    branches = api.get_json(GITHUB, GH_ENV + '/deployment-branch-policies')
    policy_ready(repo, environment, branches)
    token = env.get('HOSTINGER_API_TOKEN')
    if not isinstance(token, str) or not re.fullmatch(r'[!-~]{1,4096}', token):
        raise Refused('HOSTINGER_API_TOKEN_NOT_CONFIGURED')
    vms = api.get_json(PROVIDER, VM_PATH, token)
    if not isinstance(vms, list) or not 0 < len(vms) <= 64:
        raise Refused('BOUNDED_VM_ARRAY_REQUIRED')
    candidates = [vm for vm in vms if isinstance(vm, dict) and isinstance(vm.get('ipv4'), list)
                  and any(isinstance(ip, dict) and ip.get('address') == EXPECTED_IP for ip in vm['ipv4'])]
    if len(candidates) != 1:
        raise Refused('ONE_FIXED_IP_RESOURCE_REQUIRED')
    vm_id = bound_vm(candidates[0])  # Never derives numeric ID from srv1687281 label.
    vm = api.get_json(PROVIDER, VM_PATH + '/' + str(vm_id), token)
    bound_vm(vm, vm_id)  # Rebind list/detail before querying only this VM's keys.
    keys = api.get_json(PROVIDER, VM_PATH + '/' + str(vm_id) + '/ssh-keys', token)
    if not isinstance(keys, list) or len(keys) > 256 or any(not isinstance(key, dict) for key in keys):
        raise Refused('BOUNDED_ROOT_KEY_ARRAY_REQUIRED')
    state = vm.get('state')
    return dict(status='READ_ONLY_RESOURCE_BOUND', resource='hostinger:srv1687281', domain='jsmjapan.com',
                source_sha=env['GITHUB_SHA'], workflow_run_url='https://github.com/' + REPO + '/actions/runs/' + env['GITHUB_RUN_ID'],
                hostname=EXPECTED_HOSTNAME, ip=EXPECTED_IP, vm_id=vm_id,
                vm_state=state if state in ('running', 'stopped', 'suspended') else 'UNKNOWN',
                root_ssh_key_count=len(keys), ssh_options_preservation='UNVERIFIED',
                temporary_access_cleanup='UNVERIFIED', bootstrap_access='NOT_CONFIGURED',
                provider_mutations='NOT_PERFORMED', apache_channel='NOT_ACTIVATED',
                token_scope='INHERITS_CREATOR_PERMISSIONS_NOT_PROVEN_READ_ONLY')


def main():
    def expired(*_):
        raise Refused('OVERALL_DEADLINE')
    try:
        if len(os.sys.argv) != 1:
            raise Refused('NO_INPUTS_OR_ARGUMENTS_ACCEPTED')
        signal.signal(signal.SIGALRM, expired)
        signal.setitimer(signal.ITIMER_REAL, DEADLINE_SECONDS)
        result = collect(Api(), os.environ)
        result['verified_at_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')
        print(json.dumps(result, sort_keys=True))
        return 0
    except Exception as error:
        reason = str(error) if isinstance(error, Refused) else 'INTERNAL_SCHEMA_OR_TRANSPORT_REJECTED'
        print(json.dumps(dict(status='BLOCKED', reason=reason, provider_mutations='NOT_PERFORMED',
                              ssh_options_preservation='UNVERIFIED', apache_channel='NOT_ACTIVATED'), sort_keys=True))
        return 1
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)


if __name__ == '__main__':
    raise SystemExit(main())
