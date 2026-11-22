"""Passive, scoped FPM socket witness for the existing TEST metadata profile."""

REASONS = ('NONE', 'UNIT_UNAVAILABLE', 'NO_STABLE_WITNESS',
           'STABILITY_NOT_CONFIRMED', 'METADATA_REFUSED', 'DEADLINE')

LIBRARY = r'''
import ipaddress
import sys

def _php_endpoint_receipt(reason):
    found=reason=='NONE'
    return dict(state='OBSERVED' if found else 'UNKNOWN',reason=reason,
        fpm_worker_loopback_3306=True if found else None,api_route='UNKNOWN',pool='UNKNOWN',
        forwarding='UNKNOWN',mysql_container='UNKNOWN',schema='UNKNOWN')

def _php_root_identity(pid,deadline):
    if not _pid_ready(pid):raise ValueError()
    # Follow only the kernel's typed /proc PID root link. Read no target entries.
    fds,name=_parents('/proc/'+str(pid)+'/root',deadline)
    try:
        _check(deadline)
        before=os.stat(name,dir_fd=fds[-1],follow_symlinks=False)
        if not stat.S_ISLNK(before.st_mode):raise ValueError()
        target=os.stat(name,dir_fd=fds[-1],follow_symlinks=True)
        if not stat.S_ISDIR(target.st_mode) or _stamp(before)!=_stamp(os.stat(name,dir_fd=fds[-1],follow_symlinks=False)):
            raise ValueError()
        return target.st_dev,target.st_ino
    finally:
        for fd in reversed(fds):os.close(fd)

def _php_endpoint_identity(pid,deadline):
    if not _pid_ready(pid):raise ValueError()
    prefix='/proc/'+str(pid)
    line=_proc_read(prefix+'/stat',deadline,4096)
    start=_proc_start(line,pid)
    if start<=0:raise ValueError()
    state,parent=line.rsplit(') ',1)[1].split()[:2]
    if state not in ('R','S','D','T','t','P','I') or not re.fullmatch('[0-9]{1,10}',parent) or not _pid_ready(int(parent)):
        raise ValueError()
    if _readlink(prefix+'/exe',deadline)!=EXES['php']:raise ValueError()
    namespaces=tuple(_readlink(prefix+'/ns/'+axis,deadline) for axis in ('net','mnt','pid'))
    if any(not re.fullmatch(axis+r':\[[0-9]{1,20}\]',value) for axis,value in zip(('net','mnt','pid'),namespaces)):
        raise ValueError()
    return start,int(parent),namespaces,_php_root_identity(pid,deadline)

def _php_peer_address(token,size):
    address,separator,port=token.partition(':')
    if separator!=':' or not re.fullmatch('[0-9A-F]{'+str(size*2)+'}',address) or not re.fullmatch('[0-9A-F]{4}',port):
        raise ValueError()
    packed=bytes.fromhex(address)
    if sys.byteorder=='little':packed=b''.join(packed[i:i+4][::-1] for i in range(0,size,4))
    return ipaddress.ip_address(packed),int(port,16)

def _php_tcp_peers(text,size,inodes,deadline):
    lines=text.splitlines()
    if not lines or lines[0].split()[:4] not in (
            ['sl','local_address','rem_address','st'],['sl','local_address','remote_address','st']):
        raise ValueError()
    matches={}
    for line in lines[1:]:
        _check(deadline)
        fields=line.split()
        if (len(fields)<10 or not re.fullmatch('[0-9]{1,10}:',fields[0])
                or not re.fullmatch('[0-9A-F]{2}',fields[3]) or not re.fullmatch('[0-9]{1,20}',fields[9])):
            raise ValueError()
        inode=int(fields[9])
        if inode not in inodes:continue
        if inode in matches:raise ValueError()
        local=_php_peer_address(fields[1],size)
        peer=_php_peer_address(fields[2],size)
        matches[inode]=(local,peer) if fields[3]=='01' and peer[1]==3306 else None
    return matches

def _php_endpoint_sample(master,deadline):
    identity=_php_endpoint_identity(master,deadline)
    _,_,namespaces,root=identity
    own=os.getpid()
    if not _pid_ready(own) or namespaces[0]!=_readlink('/proc/'+str(own)+'/ns/net',deadline):
        raise ValueError()
    listener=_unix_snapshot_detailed(deadline).get('php')
    if not listener or listener not in _fd_sockets(master,deadline):return None
    prefix='/proc/'+str(master)
    children=_proc_read(prefix+'/task/'+str(master)+'/children',deadline,256).split()
    if len(children)>16 or any(not re.fullmatch('[1-9][0-9]{0,9}',child) for child in children):
        raise ValueError()
    pids={int(child) for child in children}
    if master in pids or len(pids)!=len(children):raise ValueError()
    workers={}
    for pid in sorted(pids):
        stamp=_php_endpoint_identity(pid,deadline)
        if stamp[1]!=master or stamp[2]!=namespaces or stamp[3]!=root or stamp[0]<identity[0]:
            raise ValueError()
        sockets=_fd_sockets(pid,deadline)
        if listener in sockets:workers[pid]=(stamp,sockets)
    if not workers:return None
    inodes=set().union(*(sockets for _,sockets in workers.values()))
    net='/proc/'+str(own)+'/net/'
    v4=_php_tcp_peers(_proc_read(net+'tcp',deadline),4,inodes,deadline)
    v6=_php_tcp_peers(_proc_read(net+'tcp6',deadline),16,inodes,deadline)
    if v4.keys() & v6.keys():raise ValueError()
    peers=dict(v4);peers.update(v6)
    matches=[(pid,stamp,inode,peers[inode]) for pid,(stamp,sockets) in workers.items()
        for inode in sockets & peers.keys() if peers[inode] is not None]
    if len(matches)!=1:return None
    pid,stamp,inode,(local,peer)=matches[0]
    if not local[0].is_loopback or not peer[0].is_loopback:return None
    return identity,listener,pid,stamp,inode,local,peer

def _observe_php_endpoint(first,last,deadline):
    if first is None or last is None or first!=last:return _php_endpoint_receipt('UNIT_UNAVAILABLE')
    unit=first['php']
    if unit['load']!='loaded' or unit['active']!='active' or not _pid_ready(unit['pid']):
        return _php_endpoint_receipt('UNIT_UNAVAILABLE')
    try:
        _check(deadline)
        before=_php_endpoint_sample(unit['pid'],deadline)
        _check(deadline)
        if before is None:return _php_endpoint_receipt('NO_STABLE_WITNESS')
        after=_php_endpoint_sample(unit['pid'],deadline)
        _check(deadline)
        if before!=after or _unit_snapshot(deadline)!=last:
            return _php_endpoint_receipt('STABILITY_NOT_CONFIRMED')
        _check(deadline)
        return _php_endpoint_receipt('NONE')
    except (OSError,ValueError,UnicodeError,subprocess.SubprocessError) as error:
        reason='DEADLINE' if time.monotonic()>=deadline or _error_code(error)=='DEADLINE' else 'METADATA_REFUSED'
        return _php_endpoint_receipt(reason)
'''


def project_php_endpoint(value):
    unknown = ('api_route', 'pool', 'forwarding', 'mysql_container', 'schema')
    if (type(value) is not dict or set(value) != {'state', 'reason', 'fpm_worker_loopback_3306', *unknown}
            or any(value[key] != 'UNKNOWN' for key in unknown)
            or type(value['reason']) is not str or value['reason'] not in REASONS):
        return None
    found = value['reason'] == 'NONE'
    if value['state'] != ('OBSERVED' if found else 'UNKNOWN') or value['fpm_worker_loopback_3306'] is not (True if found else None):
        return None
    return value
