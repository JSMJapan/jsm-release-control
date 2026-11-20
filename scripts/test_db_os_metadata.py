"""Fixed Linux OS observations only; no SQL, connection, config or data reads.

The library is carried by the existing protected TEST transport. Its only
variable paths contain typed systemd MainPIDs or bounded numeric FD names.
Raw process links, mount paths and socket-table entries never leave the child.
"""

LIBRARY = r'''
import hashlib,json,os,re,selectors,signal,stat,subprocess,time
ROLES=('apache','php','mysql')
UNITS={'apache':'apache2.service','php':'php7.4-fpm.service','mysql':'mysql.service'}
EXES={'apache':'/usr/sbin/apache2','php':'/usr/sbin/php-fpm7.4','mysql':'/usr/sbin/mysqld'}
SOCKETS={'php':'/run/php/php7.4-fpm.sock','mysql':'/run/mysqld/mysqld.sock'}
os_geteuid=os.geteuid
def _check(deadline):
    if time.monotonic()>=deadline: raise ValueError()
def _parents(path,deadline):
    fds=[]
    try:
        if not path.startswith('/') or any(p in ('','.','..') for p in path[1:].split('/')): raise ValueError()
        _check(deadline);fds.append(os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW))
        for part in path[1:].split('/')[:-1]:
            _check(deadline);fds.append(os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fds[-1]))
        return fds,path.rsplit('/',1)[1]
    except BaseException:
        for fd in reversed(fds):os.close(fd)
        raise
def _stamp(s):
    return s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_ctime_ns
def _proc_read(path,deadline,limit=65536):
    fds=[];fd=None
    try:
        fds,name=_parents(path,deadline)
        fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fds[-1])
        before=os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1:raise ValueError()
        data=bytearray()
        while True:
            _check(deadline);chunk=os.read(fd,min(4096,limit+1-len(data)))
            if not chunk:break
            data.extend(chunk)
            if len(data)>limit:raise ValueError()
        # procfs reports size zero; exact length is intentionally not compared.
        if _stamp(before)!=_stamp(os.fstat(fd)) or _stamp(before)!=_stamp(os.stat(name,dir_fd=fds[-1],follow_symlinks=False)):raise ValueError()
        return data.decode('utf-8')
    finally:
        if fd is not None:os.close(fd)
        for directory in reversed(fds):os.close(directory)
def _readlink(path,deadline):
    fds=[]
    try:
        fds,name=_parents(path,deadline);_check(deadline)
        before=os.stat(name,dir_fd=fds[-1],follow_symlinks=False)
        if not stat.S_ISLNK(before.st_mode):raise ValueError()
        value=os.readlink(name,dir_fd=fds[-1])
        if len(value)>4096 or _stamp(before)!=_stamp(os.stat(name,dir_fd=fds[-1],follow_symlinks=False)):raise ValueError()
        return value
    finally:
        for directory in reversed(fds):os.close(directory)
def _parse_units(text):
    if type(text)is not str or len(text)>4096:raise ValueError()
    result={}
    for block in text.strip().split('\n\n'):
        values={}
        for line in block.splitlines():
            key,sep,value=line.partition('=')
            if not sep or key not in ('Id','LoadState','ActiveState','MainPID') or key in values:raise ValueError()
            values[key]=value
        if set(values)!={'Id','LoadState','ActiveState','MainPID'}:raise ValueError()
        roles=[r for r in ROLES if UNITS[r]==values['Id']]
        if len(roles)!=1 or roles[0] in result:raise ValueError()
        if values['LoadState'] not in ('loaded','not-found','masked','error') or values['ActiveState'] not in ('active','inactive','failed','activating','deactivating'):raise ValueError()
        if not re.fullmatch('0|[1-9][0-9]{0,9}',values['MainPID']):raise ValueError()
        pid=int(values['MainPID'])
        if pid>2147483647:raise ValueError()
        result[roles[0]]=dict(load=values['LoadState'],active=values['ActiveState'],pid=pid)
    if set(result)!=set(ROLES):raise ValueError()
    return result
def _unit_snapshot(deadline):
    path='/usr/bin/systemctl';fds=[];process=None
    try:
        fds,name=_parents(path,deadline);s=os.stat(name,dir_fd=fds[-1],follow_symlinks=False)
        if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_mode&0o022:raise ValueError()
        command=[path,'show','--no-pager','--property=Id,LoadState,ActiveState,MainPID',UNITS['apache'],UNITS['php'],UNITS['mysql']]
        process=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
            start_new_session=True,env={'PATH':'/usr/bin:/bin','LANG':'C'})
        data=bytearray();eof=False;until=min(deadline,time.monotonic()+.7)
        with selectors.DefaultSelector() as ready:
            ready.register(process.stdout,selectors.EVENT_READ)
            while time.monotonic()<until:
                for key,_ in ready.select(min(.05,max(0,until-time.monotonic()))):
                    chunk=os.read(key.fileobj.fileno(),min(4096,4097-len(data)));data.extend(chunk)
                    if len(data)>4096:raise ValueError()
                    if not chunk:eof=True;break
                if eof:break
        remaining=until-time.monotonic()
        if not eof or remaining<=0 or process.wait(timeout=remaining)!=0:raise ValueError()
        return _parse_units(data.decode('ascii'))
    finally:
        if process is not None:
            try:os.killpg(process.pid,signal.SIGKILL)
            except OSError:pass
            if process.poll()is None:
                try:process.wait(timeout=max(.01,min(.1,deadline-time.monotonic())))
                except subprocess.TimeoutExpired:pass
            process.stdout.close()
        for directory in reversed(fds):os.close(directory)
def _proc_start(text,pid):
    if type(text)is not str or not text.startswith(str(pid)+' (') or len(text)>4096:raise ValueError()
    close=text.rfind(') ')
    if close<0:raise ValueError()
    fields=text[close+2:].split()
    if len(fields)<20 or not re.fullmatch('[0-9]{1,20}',fields[19]):raise ValueError()
    return int(fields[19])
def _pid_ready(pid):
    return type(pid)is int and 0<pid<=2147483647
def _fd_sockets(pid,deadline):
    fds=[];fd=None;found=set();count=0
    try:
        if not _pid_ready(pid):raise ValueError()
        fds,name=_parents('/proc/'+str(pid)+'/fd',deadline)
        fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fds[-1])
        with os.scandir(fd) as entries:
            for entry in entries:
                _check(deadline);count+=1
                if count>128 or not re.fullmatch('[0-9]{1,10}',entry.name):raise ValueError()
                target=os.readlink(entry.name,dir_fd=fd)
                if len(target)>4096:raise ValueError()
                match=re.fullmatch(r'socket:\[([0-9]{1,20})\]',target)
                if match:found.add(int(match[1]))
        return found
    finally:
        if fd is not None:os.close(fd)
        for directory in reversed(fds):os.close(directory)
def _proc_snapshot(role,pid,deadline):
    result=dict(state='unknown',start=None,exe_matches=None,namespace_matches=None,sockets=set())
    try:
        if role not in ROLES or not _pid_ready(pid):return result
        prefix='/proc/'+str(pid);own='/proc/'+str(os.getpid())
        start=_proc_start(_proc_read(prefix+'/stat',deadline,4096),pid)
        exe=_readlink(prefix+'/exe',deadline)
        result['exe_matches']=exe==EXES[role]
        same=True
        for namespace in ('net','mnt'):
            observed=_readlink(prefix+'/ns/'+namespace,deadline);observer=_readlink(own+'/ns/'+namespace,deadline)
            if not re.fullmatch(namespace+r':\[[0-9]{1,20}\]',observed) or not re.fullmatch(namespace+r':\[[0-9]{1,20}\]',observer):raise ValueError()
            same=same and observed==observer
        result['namespace_matches']=same
        if not result['exe_matches'] or not same:return result
        sockets=_fd_sockets(pid,deadline)
        if not _proc_still_same(role,pid,start,deadline):return result
        result.update(state='observed',start=start,sockets=sockets)
    except (OSError,ValueError,UnicodeError):pass
    return result
def _proc_still_same(role,pid,start,deadline):
    try:
        prefix='/proc/'+str(pid);own='/proc/'+str(os.getpid())
        if (_proc_start(_proc_read(prefix+'/stat',deadline,4096),pid)!=start
                or _readlink(prefix+'/exe',deadline)!=EXES[role]):return False
        for namespace in ('net','mnt'):
            observed=_readlink(prefix+'/ns/'+namespace,deadline);observer=_readlink(own+'/ns/'+namespace,deadline)
            if not re.fullmatch(namespace+r':\[[0-9]{1,20}\]',observed) or observed!=observer:return False
        return True
    except (OSError,ValueError,UnicodeError):return False
def _parse_unix(text):
    if type(text)is not str or len(text.encode('utf-8'))>65536:raise ValueError()
    result={};matches={r:[] for r in SOCKETS}
    lines=text.splitlines()
    if not lines or not lines[0].split() or lines[0].split()[-1]!='Path':raise ValueError()
    for line in lines[1:]:
        fields=line.split(None,7)
        if len(fields)<7:raise ValueError()
        if len(fields)<8:continue
        for role,path in SOCKETS.items():
            if fields[7]!=path:continue
            valid=(re.fullmatch('[0-9a-fA-F]+:',fields[0]) is not None and fields[3]=='00010000'
                and fields[4]=='0001' and fields[5]=='01' and re.fullmatch('[0-9]{1,20}',fields[6])is not None)
            matches[role].append(int(fields[6]) if valid else None)
    for role,items in matches.items():
        result[role]=items[0] if len(items)==1 and items[0] is not None else None
    return result
def _unix_snapshot(deadline):
    return _parse_unix(_proc_read('/proc/'+str(os.getpid())+'/net/unix',deadline))
def _object_metadata(path,deadline,kind):
    fds=[];fd=None
    try:
        fds,name=_parents(path,deadline);before=os.stat(name,dir_fd=fds[-1],follow_symlinks=False)
        correct=stat.S_ISSOCK(before.st_mode) if kind=='socket' else stat.S_ISDIR(before.st_mode)
        if not correct or stat.S_ISLNK(before.st_mode):raise ValueError()
        if kind=='directory':
            fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fds[-1])
            if _stamp(before)!=_stamp(os.fstat(fd)):raise ValueError()
        if _stamp(before)!=_stamp(os.stat(name,dir_fd=fds[-1],follow_symlinks=False)):raise ValueError()
        result=dict(state='observed',identity=_stamp(before))
        if kind=='socket':result['is_socket']=True
        else:result.update(is_directory=True,device=(os.major(before.st_dev),os.minor(before.st_dev)))
        return result
    except (OSError,ValueError):
        return dict(state='unknown',**({'is_socket':None} if kind=='socket' else {'is_directory':None,'device':None}))
    finally:
        if fd is not None:os.close(fd)
        for directory in reversed(fds):os.close(directory)
def _socket_metadata(role,deadline):return _object_metadata(SOCKETS[role],deadline,'socket')
def _datadir_metadata(deadline):return _object_metadata('/var/lib/mysql',deadline,'directory')
def _parse_mount(text,device):
    unknown=dict(state='unknown',filesystem='unknown',device_matches=None)
    if type(text)is not str or len(text.encode('utf-8'))>65536 or type(device)is not tuple or len(device)!=2:return unknown
    choices=[];target='/var/lib/mysql'
    for line in text.splitlines():
        if line.count(' - ')!=1:return unknown
        left,right=line.split(' - ');a=left.split();b=right.split()
        if len(a)<6 or len(b)<3 or not re.fullmatch('[0-9]+:[0-9]+',a[2]):return unknown
        mount=a[4]
        if not mount.startswith('/') or any(p in ('.','..') for p in mount.split('/')):return unknown
        if '\\' in mount:continue
        if target==mount or target.startswith(mount.rstrip('/')+'/'):
            choices.append((len(mount),a[2],b[0],b[1]))
    if not choices:return unknown
    longest=max(row[0] for row in choices);selected=[r for r in choices if r[0]==longest]
    if len(selected)!=1:return unknown
    _,dev,filesystem,source=selected[0]
    if tuple(map(int,dev.split(':')))!=device:return unknown
    local=filesystem in ('ext4','xfs','btrfs') and source.startswith('/dev/')
    return dict(state='observed',filesystem='local_block' if local else 'unsupported',device_matches=True)
def _mount_snapshot(device,deadline):
    text=_proc_read('/proc/'+str(os.getpid())+'/mountinfo',deadline)
    result=_parse_mount(text,device)
    result['_identity']=hashlib.sha256(text.encode('utf-8')).hexdigest()
    return result
def _observe(nonce):
    if type(nonce)is not str or not re.fullmatch('[0-9a-f]{32}',nonce):raise ValueError()
    deadline=time.monotonic()+3
    result=dict(version='jsm-test-db-os-2760-v1',nonce=nonce,euid=os_geteuid(),observation_state='PARTIAL',
        processes=[dict(id=r,state='unknown',exe_matches=None,namespace_matches=None,stable=None) for r in ROLES],
        sockets=[dict(id=r,state='unknown',is_socket=None,kernel_listener=None,owned_by_service_mainpid=None) for r in ('php','mysql')],
        datadir=dict(state='unknown',is_directory=None,filesystem='unknown',device_matches=None),
        effective_api_binding='NOT_ESTABLISHED',test_disk_identity='NOT_ESTABLISHED',db_proof='BLOCKED_TARGET_ADMISSION',sql='NOT_ATTEMPTED')
    if result['euid']!=0:return result
    observed={};first=None;last=None;unix={};socket_metadata={};mount=None
    try:
        first=_unit_snapshot(deadline)
        for role,row in zip(ROLES,result['processes']):
            unit=first[role]
            if unit['load']!='loaded' or unit['active']!='active' or not _pid_ready(unit['pid']):continue
            proc=_proc_snapshot(role,unit['pid'],deadline);observed[role]=proc
            row.update(state=proc['state'],exe_matches=proc['exe_matches'],namespace_matches=proc['namespace_matches'])
        unix=_unix_snapshot(deadline)
        for role,row in zip(('php','mysql'),result['sockets']):
            fs=_socket_metadata(role,deadline);socket_metadata[role]=fs
            row.update(state=fs['state'],is_socket=fs['is_socket'])
            inode=unix.get(role);row['kernel_listener']=inode is not None
            proc=observed.get(role)
            if fs['is_socket'] is True and inode is not None and proc and proc['state']=='observed':
                row['owned_by_service_mainpid']=inode in proc['sockets']
        directory=_datadir_metadata(deadline)
        result['datadir'].update(state=directory['state'],is_directory=directory['is_directory'])
        if directory['state']=='observed':
            mount=_mount_snapshot(directory['device'],deadline)
            result['datadir'].update({k:mount[k] for k in ('state','filesystem','device_matches')})
        last=_unit_snapshot(deadline)
        last_unix=_unix_snapshot(deadline)
        for role,row in zip(ROLES,result['processes']):
            proc=observed.get(role)
            again=(_proc_snapshot(role,first[role]['pid'],deadline)
                if proc and proc['state']=='observed' and first==last else None)
            stable=(first==last and proc is not None and proc['state']=='observed'
                and again is not None and again['state']=='observed' and again['start']==proc['start']
                and again['exe_matches'] is True and again['namespace_matches'] is True
                and _proc_still_same(role,first[role]['pid'],proc['start'],deadline))
            row['stable']=stable if proc and proc['state']=='observed' else None
            if not stable:
                row['state']='unknown'
                for socket in result['sockets']:
                    if socket['id']==role:socket['owned_by_service_mainpid']=None
            elif role in SOCKETS:
                fs_again=_socket_metadata(role,deadline)
                old=socket_metadata[role];inode=unix.get(role)
                same=(old==fs_again and inode is not None and last_unix.get(role)==inode
                    and (inode in proc['sockets'])==(inode in again['sockets']))
                if not same:
                    for socket in result['sockets']:
                        if socket['id']==role:socket.update(state='unknown',owned_by_service_mainpid=None)
        directory_again=_datadir_metadata(deadline)
        if directory!=directory_again or (mount is not None and mount!=_mount_snapshot(directory_again['device'],deadline)):
            result['datadir']=dict(state='unknown',is_directory=None,filesystem='unknown',device_matches=None)
        if (all(r['state']=='observed' and r['stable'] is True for r in result['processes'])
                and all(r['owned_by_service_mainpid'] is True for r in result['sockets'])
                and result['datadir']==dict(state='observed',is_directory=True,filesystem='local_block',device_matches=True)):
            result['observation_state']='OBSERVED'
    except (OSError,ValueError,UnicodeError,subprocess.SubprocessError):
        for row in result['processes']:row.update(state='unknown',stable=None)
        for row in result['sockets']:row['owned_by_service_mainpid']=None
    return result
'''
