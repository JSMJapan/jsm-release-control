"""GitHub provenance and protected approval for a finite Eva TEST operation."""

import re

from apache_parity_bridge import strict_json
from article_test_actions import OWNER_ID, REPO, SOURCE_API, SOURCE_REPO
from hostinger_preflight import policy_ready
from eva_test_archive import ARCHIVE_LIMIT, require

WORKFLOW = '.github/workflows/eva-isolated-stage-1620.yml'
PACKAGE_WORKFLOW = '.github/workflows/eva-isolated-test-package-1620.yml'
ENVIRONMENT = 'eva-isolated-stage-1620'
CONTROL = '/repos/' + REPO
REPO_ID = 1427965640
ARTIFACT_STEPS = (
    'Check out the exact Eva package source',
    'Check out the exact PHP bridge candidate',
    'Check out the exact Telegram runner candidate',
    'Build both dedicated Eva images',
    'Prove a real PHP and MySQL owner cycle with synthetic providers',
    'Prepare the checksummed private package',
    'Upload the verified Eva package to the private repository',
)


def owner(row):
    return type(row) is dict and row.get('login') == 'JSMJapan' and row.get('id') == OWNER_ID


def repo_matches(row, name, identity, private):
    return (type(row) is dict and row.get('full_name') == name and row.get('id') == identity
            and row.get('private') is private)


def control_paths(run_id, *, environment_name=ENVIRONMENT):
    env = CONTROL + '/environments/' + environment_name
    run = CONTROL + '/actions/runs/' + run_id
    return (
        CONTROL, env, env + '/deployment-branch-policies', CONTROL + '/branches/main',
        CONTROL + '/actions/workflows/' + WORKFLOW.rsplit('/', 1)[1], run, run + '/approvals',
    )


def authorize(api, env, run_id, sha, *, environment_name=ENVIRONMENT, job='install'):
    fixed = {
        'GITHUB_REPOSITORY': REPO, 'GITHUB_EVENT_NAME': 'workflow_dispatch', 'GITHUB_ACTOR': 'JSMJapan',
        'GITHUB_TRIGGERING_ACTOR': 'JSMJapan', 'GITHUB_REF': 'refs/heads/main', 'GITHUB_RUN_ATTEMPT': '1',
        'GITHUB_SERVER_URL': 'https://github.com', 'GITHUB_API_URL': 'https://api.github.com',
        'GITHUB_JOB': job, 'GITHUB_WORKFLOW_REF': REPO + '/' + WORKFLOW + '@refs/heads/main',
        'GITHUB_WORKFLOW_SHA': sha, 'GITHUB_SHA': sha, 'APPROVED_SHA': sha, 'GITHUB_RUN_ID': run_id,
    }
    require(all(env.get(k) == value for k, value in fixed.items()), 'EVA_GITHUB_CONTEXT_REFUSED')
    repo, environment, policies, branch, work, run, approvals = [api.get_json(path) for path in control_paths(run_id, environment_name=environment_name)]
    policy_ready(repo, environment, policies)
    reviewers = [item for item in environment['protection_rules'] if item['type'] == 'required_reviewers']
    require(repo_matches(repo, REPO, REPO_ID, False) and owner(repo.get('owner'))
            and type(environment.get('id')) is int and environment.get('name') == environment_name
            and owner(reviewers[0]['reviewers'][0]['reviewer']), 'EVA_GITHUB_APPROVAL_REFUSED')
    require(branch.get('name') == 'main' and branch.get('protected') is True and branch.get('commit', {}).get('sha') == sha
            and work.get('path') == WORKFLOW and work.get('state') == 'active' and type(work.get('id')) is int
            and run.get('path') == WORKFLOW and run.get('workflow_id') == work['id']
            and run.get('head_sha') == sha and run.get('head_branch') == 'main' and run.get('event') == 'workflow_dispatch'
            and run.get('status') == 'in_progress' and run.get('id') == int(run_id) and run.get('run_attempt') == 1
            and all(repo_matches(run.get(k), REPO, REPO_ID, False) for k in ('repository', 'head_repository'))
            and all(owner(run.get(k)) for k in ('actor', 'triggering_actor')), 'EVA_GITHUB_CONTEXT_REFUSED')
    require(type(approvals) is list and len(approvals) == 1, 'EVA_GITHUB_APPROVAL_REFUSED')
    review = approvals[0]
    targets = review.get('environments')
    require(review.get('state') == 'approved' and owner(review.get('user'))
            and type(targets) is list and len(targets) == 1
            and targets[0].get('id') == environment['id'] and targets[0].get('name') == environment_name,
            'EVA_GITHUB_APPROVAL_REFUSED')


def artifact_paths(build):
    run = SOURCE_API + '/actions/runs/' + build.run_id
    return (SOURCE_API, run, run + '/artifacts', run + '/attempts/1/jobs?per_page=100',
            SOURCE_API + '/actions/artifacts/' + build.artifact_id)


def authorize_artifact(api, build):
    repo, run, listing, jobs, item = [api.get_json(path) for path in artifact_paths(build)]
    repo_id = repo.get('id')
    require(type(repo_id) is int and repo_id > 0 and repo_matches(repo, SOURCE_REPO, repo_id, True)
            and owner(repo.get('owner'))
            and all(repo_matches(run.get(k), SOURCE_REPO, repo_id, True) for k in ('repository', 'head_repository'))
            and run.get('event') == 'pull_request' and run.get('path') == PACKAGE_WORKFLOW
            and run.get('status') == 'completed' and run.get('conclusion') == 'success'
            and run.get('head_sha') == build.sha and run.get('run_attempt') == 1
            and run.get('id') == int(build.run_id), 'EVA_ARTIFACT_SCOPE_REFUSED')
    require(jobs.get('total_count') == 1 and type(jobs.get('jobs')) is list and len(jobs['jobs']) == 1,
            'EVA_ARTIFACT_SCOPE_REFUSED')
    job = jobs['jobs'][0]
    require(job.get('name') == 'package' and job.get('status') == 'completed' and job.get('conclusion') == 'success'
            and job.get('head_sha') == build.sha and job.get('run_id') == int(build.run_id)
            and type(job.get('steps')) is list and len(job['steps']) <= 32, 'EVA_ARTIFACT_SCOPE_REFUSED')
    completed = [step['name'] for step in job['steps'] if step.get('status') == 'completed' and step.get('conclusion') == 'success']
    require([name for name in completed if name in ARTIFACT_STEPS] == list(ARTIFACT_STEPS), 'EVA_ARTIFACT_SCOPE_REFUSED')
    linked = item.get('workflow_run', {})
    size = item.get('size_in_bytes')
    require(listing.get('total_count') == 1 and listing.get('artifacts') == [item]
            and item.get('id') == int(build.artifact_id) and item.get('name') == build.artifact_name
            and item.get('expired') is False and item.get('digest') == 'sha256:' + build.archive_sha256
            and type(size) is int and 0 < size <= ARCHIVE_LIMIT and linked.get('id') == int(build.run_id)
            and linked.get('head_sha') == build.sha, 'EVA_ARTIFACT_SCOPE_REFUSED')
    return size


def preflight_paths(run_id):
    root = CONTROL + '/actions/runs/' + run_id
    return root, root + '/attempts/1/jobs', root + '/approvals'


def preflight_binding(get, run_id, sha, now):
    from datetime import datetime

    evidence = 'EVA_ROUTE_PREFLIGHT_REFUSED'
    require(type(run_id) is str and re.fullmatch('[1-9][0-9]{0,14}', run_id), evidence)
    run, jobs, approvals = [get(path) for path in preflight_paths(run_id)]
    require(run.get('id') == int(run_id) and run.get('head_sha') == sha and run.get('head_branch') == 'main'
            and run.get('path') == WORKFLOW and run.get('run_attempt') == 1 and run.get('event') == 'workflow_dispatch'
            and run.get('status') == 'completed' and run.get('conclusion') == 'success'
            and all(owner(run.get(field)) for field in ('actor', 'triggering_actor'))
            and all(repo_matches(run.get(field), REPO, REPO_ID, False) for field in ('repository', 'head_repository')), evidence)
    require(type(approvals) is list and len(approvals) == 1 and approvals[0].get('state') == 'approved'
            and owner(approvals[0].get('user')) and
            [item.get('name') for item in approvals[0].get('environments', [])] == ['test-api-readonly-access'], evidence)
    rows = [item for item in jobs.get('jobs', []) if item.get('name') == 'Owner-approved Eva receiver bootstrap on jsm-sandbox']
    require(len(rows) == 1 and rows[0].get('status') == 'completed' and rows[0].get('conclusion') == 'success', evidence)
    done = datetime.fromisoformat(rows[0]['completed_at'].replace('Z', '+00:00'))
    require(done.tzinfo is not None and 0 <= now - done.timestamp() <= 7200, evidence)
    check = rows[0].get('check_run_url', '')
    match = re.fullmatch(rf'https://api\.github\.com/repos/{REPO}/check-runs/([1-9][0-9]{{0,14}})', check)
    require(match, evidence)
    api_path = CONTROL + '/check-runs/' + match[1] + '/annotations?per_page=51'
    notes = get(api_path)
    require(type(notes) is list and len(notes) <= 50, evidence)
    annotated = [row for row in notes if row.get('title') == 'JSM Eva route preflight receipt']
    require(len(annotated) == 1 and annotated[0].get('path') == 'scripts/eva_test_bootstrap.py'
            and annotated[0].get('annotation_level') == 'notice'
            and type(annotated[0].get('message')) is str and len(annotated[0]['message']) <= 2048, evidence)
    values = strict_json(annotated[0]['message'])
    require(type(values) is dict and values.keys() == {'status', 'binding', 'control_sha', 'workflow_run'}
            and values['status'] == 'OBSERVED' and values['control_sha'] == sha
            and values['workflow_run'] == 'https://github.com/' + REPO + '/actions/runs/' + run_id, evidence)
    binding = values['binding']
    require(type(binding) is dict and binding.keys() == {'vhost_sha256', 'certificate_sha256', 'publisher_lock',
                                                         'provider_ipv4', 'log_scope', 'tls'}
            and binding['publisher_lock'] == 'OBSERVED_AND_AVAILABLE' and binding['log_scope'] == 'ADMITTED'
            and binding['tls'] == 'LOCAL_SNI_VERIFIED', evidence)
    return binding
