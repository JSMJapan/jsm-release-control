"""Fixed cgroup-v2 MySQL/PHP socket witness. Private tuples never leave here.

Reuse the reviewed Docker single-GET and proc/FD readers. No Docker inspect,
top, process scan, argv, environment, volume data or SQL is involved.
"""
import hashlib
import json
import os
import re
import stat

from test_db_os_metadata import LIBRARY as OS_LIBRARY
from test_db_php_endpoint import LIBRARY as PHP_LIBRARY
from test_db_docker_metadata import LIBRARY as DOCKER_LIBRARY, project_discovery
from test_db_docker_binding import LIBRARY as BINDING_LIBRARY
from test_php_manifest_readonly import OBSERVATION as MANIFEST_LIBRARY
from test_db_runtime_protocol import Rejected, canonical

MAX_CGROUP_PIDS = 16
MYSQL_EXES = ('/usr/sbin/mysqld', '/usr/sbin/mariadbd', '/usr/local/mysql/bin/mysqld')
PROXY_EXE = '/usr/bin/docker-proxy'


def namespace():
    ns = {}
    for library in (OS_LIBRARY, PHP_LIBRARY, DOCKER_LIBRARY, BINDING_LIBRARY, MANIFEST_LIBRARY):
        exec(library, ns)
    return ns


def target(value):
    if (type(value) is not dict or set(value) != {'host', 'port', 'schema', 'same_db'}
            or value['host'] != '127.0.0.1' or type(value['port']) is not int
            or not 1 <= value['port'] <= 65535 or value['same_db'] is not True
            or type(value['schema']) is not str
            or re.fullmatch('[A-Za-z0-9_]{1,64}', value['schema']) is None):
        raise Rejected('TARGET_REFUSED')
    return dict(value)


def cgroup_pids(text):
    if type(text) is not str or not text.isascii() or len(text) > 4096:
        raise Rejected('CGROUP_REFUSED')
    rows = text.split()
    if (not 0 < len(rows) <= MAX_CGROUP_PIDS or len(rows) != len(set(rows))
            or any(re.fullmatch('[1-9][0-9]{0,9}', row) is None or int(row) == 1 for row in rows)):
        raise Rejected('CGROUP_REFUSED')
    return tuple(sorted(map(int, rows)))


def tcp_rows(text, size, owned, address_parser, check):
    if type(text) is not str or not text.isascii() or len(text) > 65536:
        raise Rejected('TCP_REFUSED')
    rows = text.splitlines()
    if not rows or rows[0].split()[:4] not in (
            ['sl', 'local_address', 'rem_address', 'st'],
            ['sl', 'local_address', 'remote_address', 'st']):
        raise Rejected('TCP_REFUSED')
    result = {}
    for row in rows[1:]:
        check()
        fields = row.split()
        if (len(fields) < 10 or re.fullmatch('[0-9]{1,10}:', fields[0]) is None
                or re.fullmatch('[0-9A-F]{2}', fields[3]) is None
                or re.fullmatch('[0-9]{1,20}', fields[9]) is None):
            raise Rejected('TCP_REFUSED')
        inode = int(fields[9])
        if inode not in owned:
            continue
        if inode in result:
            raise Rejected('TCP_REFUSED')
        # Retain only typed connection/listener facts, not lines or other fields.
        result[inode] = (fields[3], address_parser(fields[1], size), address_parser(fields[2], size))
    return result


class Kernel:
    def __init__(self, deadline, ns=None):
        self.deadline = deadline
        self.ns = namespace() if ns is None else ns

    def check(self):
        self.ns['_check'](self.deadline)

    def discover(self):
        """One existing authenticated Docker GET; retain typed port bindings privately."""
        mappings = {}
        original = self.ns['_docker_parse_body']

        def parse(body):
            closed = original(body)
            rows = json.loads(body.decode('utf-8'), object_pairs_hook=self.ns['_docker_pairs'],
                              parse_constant=self.ns['_docker_constant'])
            for row in rows:
                bindings = []
                for port in row.get('Ports', []):
                    if (type(port) is dict and port.get('PrivatePort') == 3306 and port.get('Type') == 'tcp'
                            and type(port.get('PublicPort')) is int and port.get('IP') == '127.0.0.1'):
                        bindings.append(port['PublicPort'])
                mappings[row['Id']] = tuple(sorted(bindings))
            return closed

        self.ns['_docker_parse_body'] = parse
        try:
            first = self.ns['_additional_unit_snapshot'](self.deadline)['docker']
            pending = self.ns['_docker_begin'](first, self.deadline, binding=True)
            last = self.ns['_additional_unit_snapshot'](self.deadline)['docker']
            packet = self.ns['_docker_finish'](pending, last, self.deadline)
            binding = self.ns['_binding_public'](pending, packet)
            if (project_discovery(packet) is None or packet['state'] != 'OBSERVED'
                    or binding['state'] != 'PROVED'):
                raise Rejected('DOCKER_UNCONFIRMED')
            candidates = [row for row in packet['containers'] if row['image_family'] == 'mysql'
                          and row['image_id'] is not None and row['port3306_published'] is True
                          and row['port3306_loopback'] is True and row['port3306_nonloopback'] is False]
            if len(candidates) != 1 or len(mappings.get(candidates[0]['id'], ())) != 1:
                raise Rejected('MYSQL_CANDIDATE_REFUSED')
            row = candidates[0]
            return dict(id=row['id'], image_id=row['image_id'], port=mappings[row['id']][0])
        finally:
            self.ns['_docker_parse_body'] = original

    def cgroup(self, identity=None):
        if identity is not None and (type(identity) is not str or re.fullmatch('[0-9a-f]{64}', identity) is None):
            raise Rejected('CGROUP_REFUSED')
        relative = 'docker.service' if identity is None else 'docker-' + identity + '.scope'
        path = '/sys/fs/cgroup/system.slice/' + relative + '/cgroup.procs'
        fds, name = self.ns['_parents'](path, self.deadline)
        try:
            for fd in fds:
                self.check()
                info = os.fstat(fd)
                if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                    raise Rejected('CGROUP_REFUSED')
            info = os.stat(name, dir_fd=fds[-1], follow_symlinks=False)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise Rejected('CGROUP_REFUSED')
        finally:
            for fd in reversed(fds):
                os.close(fd)
        members = cgroup_pids(self.ns['_proc_read'](path, self.deadline, 4096))
        for pid in members:
            membership = self.ns['_proc_read']('/proc/'+str(pid)+'/cgroup', self.deadline, 4096)
            if membership != '0::/system.slice/'+relative+'\n':
                raise Rejected('CGROUP_REFUSED')
        return members

    def identity(self, pid, expected):
        if type(pid) is not int or not 1 < pid <= 2147483647:
            raise Rejected('PROCESS_REFUSED')
        start = self.ns['_proc_start'](self.ns['_proc_read']('/proc/'+str(pid)+'/stat', self.deadline, 4096), pid)
        exe = self.ns['_readlink']('/proc/'+str(pid)+'/exe', self.deadline)
        spaces = tuple(self.ns['_readlink']('/proc/'+str(pid)+'/ns/'+axis, self.deadline)
                       for axis in ('net', 'mnt', 'pid'))
        if start <= 0 or exe not in expected or any(re.fullmatch(axis+r':\[[0-9]{1,20}\]', value) is None
                                                  for axis, value in zip(('net', 'mnt', 'pid'), spaces)):
            raise Rejected('PROCESS_REFUSED')
        return (start, exe, spaces)

    def tcp(self, pid, role='DB'):
        try:
            return self._tcp(pid)
        except ValueError as error:
            known=('FD_ENTRY_LIMIT','FD_NAME_REFUSED','FD_TARGET_LIMIT','FD_DISAPPEARED','FD_ACCESS_REFUSED','FD_IO_REFUSED')
            if role in ('DB','PHP','PROXY') and len(error.args)==1 and error.args[0] in known:
                raise Rejected(role+'_'+error.args[0]) from None
            raise

    def _tcp(self, pid):
        owned = self.ns['_fd_sockets'](pid, self.deadline)
        result = {}
        for suffix, size in (('tcp', 4), ('tcp6', 16)):
            rows = tcp_rows(self.ns['_proc_read']('/proc/'+str(pid)+'/net/'+suffix, self.deadline),
                            size, owned, self.ns['_php_peer_address'], self.check)
            if result.keys() & rows.keys():
                raise Rejected('TCP_REFUSED')
            result.update(rows)
        return result

    def _member(self, members, expected, port, host=None):
        matches = []
        for pid in members:
            self.check()
            # A service/container may legitimately contain helpers. Only an
            # exact known executable is a candidate; its full identity remains
            # mandatory and is rechecked after the complete bounded scan.
            if self.ns['_readlink']('/proc/'+str(pid)+'/exe', self.deadline) not in expected:
                continue
            identity = self.identity(pid, expected)
            rows = self.tcp(pid, 'DB' if expected == MYSQL_EXES else 'PROXY')
            for inode, (state, local, peer) in rows.items():
                if state == '0A' and local[1] == port and (host is None or str(local[0]) in (host, '0.0.0.0')):
                    matches.append(dict(pid=pid, identity=identity, inode=inode, address=local))
        if len(matches) != 1:
            raise Rejected('LOCAL_LISTENER_REFUSED')
        selected = matches[0]
        if self.identity(selected['pid'], expected) != selected['identity']:
            raise Rejected('PROCESS_REFUSED')
        return selected

    def before(self, proposed):
        proposed = target(proposed)
        candidate = self.discover()
        if proposed['port'] != candidate['port']:
            raise Rejected('TARGET_REFUSED')
        members = self.cgroup(candidate['id'])
        mysql = self._member(members, MYSQL_EXES, 3306)
        own_net = self.ns['_readlink']('/proc/'+str(os.getpid())+'/ns/net', self.deadline)
        if mysql['identity'][2][0] == own_net:
            ingress = mysql
            if mysql['address'][1] != proposed['port'] or str(mysql['address'][0]) not in ('127.0.0.1', '0.0.0.0'):
                raise Rejected('TARGET_REFUSED')
            route = 'DIRECT'
        else:
            # One documented native systemd cgroup layout only. No PID/argv scan.
            ingress = self._member(self.cgroup(), (PROXY_EXE,), proposed['port'], proposed['host'])
            if ingress['identity'][2][0] != own_net:
                raise Rejected('FORWARDING_UNCONFIRMED')
            route = 'PROXY'
        return dict(candidate=candidate, members=members, mysql=mysql, ingress=ingress,
                    route=route, target=proposed)

    def _still(self, witness):
        if self.cgroup(witness['candidate']['id']) != witness['members']:
            raise Rejected('PEER_CHANGED')
        for role in ('mysql', 'ingress'):
            row = witness[role]
            expected = MYSQL_EXES if role == 'mysql' or witness['route'] == 'DIRECT' else (PROXY_EXE,)
            if self.identity(row['pid'], expected) != row['identity']:
                raise Rejected('PEER_CHANGED')
            if self.tcp(row['pid'],'DB' if role=='mysql' or witness['route']=='DIRECT' else 'PROXY').get(row['inode'], ())[:2] != ('0A', row['address']):
                raise Rejected('PEER_CHANGED')

    def peer(self, worker, witness):
        self._still(witness)
        worker_identity = self.ns['_php_endpoint_identity'](worker, self.deadline)
        if worker_identity[2][0] != witness['ingress']['identity'][2][0]:
            raise Rejected('PHP_PEER_REFUSED')
        proposed = witness['target']
        own = self.tcp(worker, 'PHP')
        php = [(inode,row) for inode,row in own.items() if row[0] == '01'
               and str(row[2][0]) == proposed['host'] and row[2][1] == proposed['port']]
        if len(php) != 1:
            raise Rejected('PHP_PEER_REFUSED')
        php_inode,(_, local, remote) = php[0]
        mysql = self.tcp(witness['mysql']['pid'])
        if witness['route'] == 'DIRECT':
            matches = [row for row in mysql.values() if row == ('01', remote, local)]
            if len(matches) != 1:
                raise Rejected('DB_PEER_REFUSED')
            legs = (local, remote)
        else:
            proxy = [row for row in self.tcp(witness['ingress']['pid'],'PROXY').values() if row[0] == '01']
            incoming = ('01', remote, local)
            outgoing = [row for row in proxy if row != incoming and row[2][1] == 3306]
            if len(proxy) != 2 or proxy.count(incoming) != 1 or len(outgoing) != 1:
                raise Rejected('FORWARDING_UNCONFIRMED')
            _, sent, received = outgoing[0]
            if sum(row == ('01', received, sent) for row in mysql.values()) != 1:
                raise Rejected('DB_PEER_REFUSED')
            legs = (local, remote, sent, received)
        self._still(witness)
        if self.ns['_php_endpoint_identity'](worker, self.deadline) != worker_identity:
            raise Rejected('PEER_CHANGED')
        if self.tcp(worker,'PHP').get(php_inode) != ('01',local,remote):
            raise Rejected('PEER_CHANGED')
        projected = [php_inode, [[str(address), port] for address, port in legs]]
        return hashlib.sha256(b'jsm-runtime-peer\0' + canonical(projected)).hexdigest()

    def fpm(self):
        return self.ns['_manifest_snapshot'](self.deadline)
