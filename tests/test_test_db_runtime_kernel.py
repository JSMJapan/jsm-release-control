"""Kernel metadata fixtures only; no TEST/Docker/FPM/DB calls."""
import ipaddress
from pathlib import Path
import sys
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from test_db_runtime_kernel import Kernel, Rejected, cgroup_pids, tcp_rows, target, PROXY_EXE


def endpoint(host, port):
    return ipaddress.ip_address(host), port


class Fixture(Kernel):
    def __init__(self, proxy=True):
        self.deadline = time.monotonic()+3
        self.reads = []
        self.ns = {'_check': lambda d: None,
                   '_readlink': self.readlink, '_php_endpoint_identity': self.worker}
        self.ids = {20: (1, '/usr/sbin/mysqld', ('net:[2]' if proxy else 'net:[1]', 'mnt:[2]', 'pid:[2]')),
                    21: (1, '/usr/bin/helper', ('net:[2]', 'mnt:[2]', 'pid:[2]')),
                    30: (1, '/usr/bin/dockerd', ('net:[1]', 'mnt:[1]', 'pid:[1]')),
                    31: (1, PROXY_EXE, ('net:[1]', 'mnt:[1]', 'pid:[1]'))}
        self.worker_ns='net:[1]'
        self.rows = {20:{100:('0A',endpoint('0.0.0.0',3306),endpoint('0.0.0.0',0))},
                     21:{},30:{},31:{101:('0A',endpoint('127.0.0.1',3306),endpoint('0.0.0.0',0))},
                     40:{201:('01',endpoint('127.0.0.1',45000),endpoint('127.0.0.1',3306))}}
        if proxy:
            self.rows[31].update({202:('01',endpoint('127.0.0.1',3306),endpoint('127.0.0.1',45000)),
                                 203:('01',endpoint('172.18.0.1',45001),endpoint('172.18.0.2',3306))})
            self.rows[20][204]=('01',endpoint('172.18.0.2',3306),endpoint('172.18.0.1',45001))
        else:
            self.rows[20][204]=('01',endpoint('127.0.0.1',3306),endpoint('127.0.0.1',45000))

    def readlink(self,path,deadline):
        self.reads.append(path)
        if path.endswith('/ns/net'):return 'net:[1]'
        return self.ids[int(path.split('/')[2])][1]

    def worker(self,pid,deadline):return (2,10,(self.worker_ns,'mnt:[9]','pid:[1]'),(1,2))
    def discover(self):return {'id':'a'*64,'image_id':'sha256:'+'b'*64,'port':3306}
    def cgroup(self,identity=None):return (20,21) if identity else (30,31)
    def identity(self,pid,expected):
        self.reads.append(('identity',pid))
        value=self.ids[pid]
        if value[1] not in expected:raise Rejected('PROCESS_REFUSED')
        return value
    def tcp(self,pid,role='DB'):return self.rows[pid]


class RuntimeKernelTests(unittest.TestCase):
    proposed=dict(host='127.0.0.1',port=3306,schema='stand',same_db=True)

    def test_actual_member_scan_skips_helper_not_identity_of_selected_endpoint(self):
        f=Fixture();w=f.before(self.proposed)
        self.assertEqual(w['route'],'PROXY')
        self.assertEqual(w['ingress']['pid'],31)
        self.assertNotIn(('identity',30),f.reads)
        self.assertNotIn(('identity',21),f.reads)
        self.assertEqual(len(f.peer(40,w)),64)

    def test_direct_flow_and_namespace_alias_attack(self):
        f=Fixture(False);w=f.before(self.proposed)
        self.assertEqual(w['route'],'DIRECT');self.assertEqual(len(f.peer(40,w)),64)
        f.worker_ns='net:[99]'
        with self.assertRaisesRegex(Rejected,'^PHP_PEER_REFUSED$'):f.peer(40,w)

    def test_proxy_ambiguous_connection_wrong_db_and_worker_namespace_refused(self):
        for mutation in ('extra','wrong_db','worker_ns','exe','listener'):
            f=Fixture();w=f.before(self.proposed)
            if mutation=='extra':f.rows[31][300]=('01',endpoint('1.1.1.1',1),endpoint('2.2.2.2',2))
            if mutation=='wrong_db':f.rows[20].pop(204)
            if mutation=='worker_ns':f.worker_ns='net:[3]'
            if mutation=='exe':f.ids[20]=(2,'/usr/bin/other',f.ids[20][2])
            if mutation=='listener':f.rows[20].pop(100)
            with self.assertRaises(Rejected):f.peer(40,w)

    def test_full_scan_no_early_success_and_duplicate_listener_refused(self):
        f=Fixture();f.ids[32]=f.ids[31];f.rows[32]=dict(f.rows[31]);f.cgroup=lambda id=None:(20,21) if id else (30,31,32)
        with self.assertRaisesRegex(Rejected,'^LOCAL_LISTENER_REFUSED$'):f.before(self.proposed)

    def test_boundaries_and_target_types(self):
        self.assertEqual(cgroup_pids('2\n3\n'),(2,3))
        for v in ('','1\n','2\n2\n','2\n'*17,'PRIVATE','²',' '.join(map(str,range(2,19)))):
            with self.assertRaises(Rejected):cgroup_pids(v)
        for field,value in [('port',True),('host','localhost'),('schema','PRIVATE;'),('same_db',1)]:
            with self.assertRaises(Rejected):target(dict(self.proposed,**{field:value}))

    def test_actual_tcp_parser_only_owned_connections_and_no_duplicate_inodes(self):
        parser=lambda text,size:endpoint('127.0.0.1',int(text.split(':')[1],16))
        header='sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n'
        row='0: 0100007F:0CEA 0100007F:AFc8 01 0 0 0 0 0 100\n'.upper()
        self.assertEqual(len(tcp_rows(header+row,4,{100},parser,lambda:None)),1)
        with self.assertRaises(Rejected):tcp_rows(header+row+row,4,{100},parser,lambda:None)
        self.assertEqual(tcp_rows(header+row,4,set(),parser,lambda:None),{})


if __name__=='__main__':unittest.main()
