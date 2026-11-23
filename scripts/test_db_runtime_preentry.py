"""Fixed stock-PHP7.4 config-file hook guard, no PHP execution.

Only this profile's selectors are parsed. Other configuration values are
private transient bytes, never returned/logged. Packaged PHP's compiled default
INI search directories are a declared platform dependency, not attested here.
"""
from contextlib import ExitStack
import hashlib
import os
import re
import selectors
import signal
import stat
import subprocess
import time
from test_db_runtime_protocol import Rejected

PROPERTIES=('Id','LoadState','ActiveState','MainPID','ExecStart')
PREFIX='etc/php/7.4/'


def launch(text,pid):
    if type(text) is not str or not text.isascii() or len(text)>8192:raise Rejected('PRE_ENTRY_UNIT_REFUSED')
    rows={}
    for line in text.splitlines():
        key,sep,value=line.partition('=')
        if not sep or key not in PROPERTIES or key in rows:raise Rejected('PRE_ENTRY_UNIT_REFUSED')
        rows[key]=value
    if (set(rows)!=set(PROPERTIES) or rows['Id']!='php7.4-fpm.service' or rows['LoadState']!='loaded'
            or rows['ActiveState']!='active' or rows['MainPID']!=str(pid)):
        raise Rejected('PRE_ENTRY_UNIT_REFUSED')
    expected='{ path=/usr/sbin/php-fpm7.4 ; argv[]=/usr/sbin/php-fpm7.4 --nodaemonize --fpm-config /etc/php/7.4/fpm/php-fpm.conf ; ignore_errors=no ; '
    value=rows['ExecStart']
    if (not value.startswith(expected) or not value.endswith(' }')
            or any(token in value[len(expected):-2] for token in ('{','}','path=','argv[]='))):
        raise Rejected('PRE_ENTRY_UNIT_REFUSED')
    # Do not retain raw argv/environment/timestamps. Only the verified active PID.
    return pid


def value(raw):
    raw=raw.strip()
    if raw[:1] in ('"',"'"):
        quote=raw[0];end=raw.find(quote,1)
        if end<0 or raw[end+1:].strip().split(';',1)[0].strip():raise Rejected('PRE_ENTRY_CONFIG_REFUSED')
        return raw[1:end]
    return raw.split(';',1)[0].strip()


def ini_selectors(raw,pool=False):
    if type(raw) is not bytes or b'\0' in raw:raise Rejected('PRE_ENTRY_CONFIG_REFUSED')
    found={};includes=[]
    try:text=raw.decode('utf-8')
    except UnicodeError:raise Rejected('PRE_ENTRY_CONFIG_REFUSED') from None
    for line in text.splitlines():
        line=line.strip()
        if not line or line[0] in ';#':continue
        if line[0]=='[':
            section=line.split(']',1)
            if len(section)!=2 or '=' in section[0] or section[1].strip().split(';',1)[0].strip():
                raise Rejected('PRE_ENTRY_CONFIG_REFUSED')
            continue
        key,sep,setting=line.partition('=')
        if not sep:raise Rejected('PRE_ENTRY_CONFIG_REFUSED')
        key=''.join(key.strip().lower().split())
        if not re.fullmatch('[a-z0-9_.\\[\\]-]+',key):raise Rejected('PRE_ENTRY_CONFIG_REFUSED')
        if key=='include':includes.append(value(setting));continue
        if pool:
            match=re.fullmatch(r'php_(?:admin_)?(?:value|flag)\[([a-z_.]+)\]',key)
            if key in ('env[phprc]','env[php_ini_scan_dir]','env[php_value]','env[php_admin_value]'):
                raise Rejected('PRE_ENTRY_ENV_REFUSED')
            key=match[1] if match else ''
        critical=('auto_prepend_file','auto_append_file','user_ini.filename')
        if key not in critical and any(item in key for item in critical):raise Rejected('PRE_ENTRY_CONFIG_REFUSED')
        if key in critical:
            setting=value(setting)
            if key=='user_ini.filename':
                if setting not in ('','.user.ini'):raise Rejected('PRE_ENTRY_CONFIG_REFUSED')
            elif setting!='':raise Rejected('PRE_ENTRY_HOOK_REFUSED')
            found[key]=setting
    return found,includes


def trusted(info):
    return info.st_uid==0 and not info.st_mode & 0o022


def stamp(info):
    return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,info.st_nlink,
            info.st_size,info.st_mtime_ns,info.st_ctime_ns)


class View:
    def __init__(self,root,deadline,before):
        self.root=root;self.deadline=deadline;self.before=before;self.records=[]
    def check(self):
        if time.monotonic()>=self.deadline:raise Rejected('DEADLINE')
    def safe(self,info,kind,aged=True):
        if (not trusted(info) or stat.S_IFMT(info.st_mode)!=kind
                or (aged and max(info.st_mtime_ns,info.st_ctime_ns)/1e9>=self.before)):
            raise Rejected('PRE_ENTRY_CHANGED')
    def parent(self,path,stack):
        if not path or any(p in ('','.','..') for p in path.split('/')):raise Rejected('PRE_ENTRY_CONFIG_REFUSED')
        parent=self.root
        for part in path.split('/')[:-1]:
            self.check();fd=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
            stack.callback(os.close,fd);self.safe(os.fstat(fd),stat.S_IFDIR,aged=False);parent=fd
        return parent,path.rsplit('/',1)[-1]
    def file(self,path,limit):
        with ExitStack() as stack:
            parent,name=self.parent(path,stack);self.check()
            fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=parent);stack.callback(os.close,fd)
            first=os.fstat(fd);self.safe(first,stat.S_IFREG)
            if first.st_nlink!=1 or first.st_size>limit:raise Rejected('PRE_ENTRY_LIMIT')
            data=bytearray()
            while True:
                self.check();part=os.read(fd,min(4096,limit+1-len(data)))
                if not part:break
                data.extend(part)
                if len(data)>limit:raise Rejected('PRE_ENTRY_LIMIT')
            if stamp(first)!=stamp(os.fstat(fd)) or stamp(first)!=stamp(os.stat(name,dir_fd=parent,follow_symlinks=False)):
                raise Rejected('PRE_ENTRY_CHANGED')
            self.records.append((path,stamp(first),hashlib.sha256(data).digest()))
            return bytes(data)
    def directory(self,path,limit):
        with ExitStack() as stack:
            parent,name=self.parent(path,stack)
            fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent);stack.callback(os.close,fd)
            first=os.fstat(fd);self.safe(first,stat.S_IFDIR)
            names=[]
            with os.scandir(fd) as rows:
                for row in rows:
                    self.check()
                    if len(names)>=limit or re.fullmatch('[A-Za-z0-9_.-]{1,96}',row.name) is None:raise Rejected('PRE_ENTRY_LIMIT')
                    names.append(row.name)
            if stamp(first)!=stamp(os.fstat(fd)) or stamp(first)!=stamp(os.stat(name,dir_fd=parent,follow_symlinks=False)):
                raise Rejected('PRE_ENTRY_CHANGED')
            self.records.append((path,stamp(first),tuple(sorted(names))))
            return sorted(names)
    def absent(self,path):
        with ExitStack() as stack:
            parent,name=self.parent(path,stack)
            try:os.stat(name,dir_fd=parent,follow_symlinks=False)
            except FileNotFoundError:return
            raise Rejected('PRE_ENTRY_SELECTION_REFUSED')
    def ini_link(self,name):
        path=PREFIX+'fpm/conf.d/'+name
        with ExitStack() as stack:
            parent,leaf=self.parent(path,stack);first=os.stat(leaf,dir_fd=parent,follow_symlinks=False)
            self.safe(first,stat.S_IFLNK)
            selected=os.readlink(leaf,dir_fd=parent)
            if re.fullmatch(r'(?:\.\./\.\./mods-available/|/etc/php/7\.4/mods-available/)[A-Za-z0-9_.-]{1,96}\.ini',selected) is None:
                raise Rejected('PRE_ENTRY_SELECTION_REFUSED')
            if stamp(first)!=stamp(os.stat(leaf,dir_fd=parent,follow_symlinks=False)):raise Rejected('PRE_ENTRY_CHANGED')
            self.records.append((path,stamp(first)))
            return self.file(PREFIX+'mods-available/'+selected.rsplit('/',1)[-1],16384)


def unit_text(ns,deadline):
    # One fixed command, no caller properties/argv/environment. Private output
    # is parsed immediately and never appears in receipt or exceptions.
    process=None
    try:
        fds,name=ns['_parents']('/usr/bin/systemctl',deadline)
        try:
            info=os.stat(name,dir_fd=fds[-1],follow_symlinks=False)
            if not stat.S_ISREG(info.st_mode) or not trusted(info) or any(not trusted(os.fstat(fd)) for fd in fds):raise Rejected('PRE_ENTRY_UNIT_REFUSED')
        finally:
            for fd in reversed(fds):os.close(fd)
        process=subprocess.Popen(['/usr/bin/systemctl','show','--no-pager','--all','--property='+','.join(PROPERTIES),'php7.4-fpm.service'],
            stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,start_new_session=True,env={'PATH':'/usr/bin:/bin','LANG':'C'})
        until=min(deadline,time.monotonic()+.2);data=bytearray();eof=False
        with selectors.DefaultSelector() as ready:
            ready.register(process.stdout,selectors.EVENT_READ)
            while time.monotonic()<until:
                for key,_ in ready.select(min(.01,max(0,until-time.monotonic()))):
                    part=os.read(key.fileobj.fileno(),min(4096,8193-len(data)));data.extend(part)
                    if len(data)>8192:raise Rejected('PRE_ENTRY_LIMIT')
                    if not part:eof=True;break
                if eof:break
        if not eof or time.monotonic()>=until:raise Rejected('DEADLINE')
        if process.wait(timeout=until-time.monotonic())!=0:raise Rejected('PRE_ENTRY_UNIT_REFUSED')
        return data.decode('ascii')
    finally:
        if process is not None:
            if process.poll() is None:
                try:os.killpg(process.pid,signal.SIGKILL)
                except OSError:pass
                try:process.wait(timeout=max(.001,min(.05,deadline-time.monotonic())))
                except subprocess.TimeoutExpired:pass
            process.stdout.close()


def observe(kernel,snapshot):
    try:return _observe(kernel,snapshot)
    except OSError:raise Rejected('PRE_ENTRY_CONFIG_REFUSED') from None


def _observe(kernel,snapshot):
    ns,deadline=kernel.ns,kernel.deadline
    master=snapshot[0]['php']['pid'];launch(unit_text(ns,deadline),master)
    # Initial environment selectors and historical worker memory are explicitly
    # NOT_ATTESTED; do not read process environment to imply otherwise.
    root=ns['_manifest_root'](snapshot,snapshot[3][0][0],deadline)
    try:
        born=time.time()-(time.clock_gettime(time.CLOCK_BOOTTIME)-snapshot[1][0]/os.sysconf('SC_CLK_TCK'))-1
        view=View(root,deadline,born)
        # FPM ignores cwd in its startup INI search. Reject higher-priority
        # SAPI/binary-directory alternatives, do not silently ignore them.
        for path in ('usr/sbin/php.ini','usr/sbin/php-fpm-fcgi.ini',PREFIX+'fpm/php-fpm-fcgi.ini'):
            view.absent(path)
        for path in ('usr/sbin',PREFIX+'fpm',PREFIX+'mods-available'):
            # Directory timestamps detect removed/added selector/INI entries.
            with ExitStack() as stack:
                parent,name=view.parent(path,stack);info=os.stat(name,dir_fd=parent,follow_symlinks=False)
                view.safe(info,stat.S_IFDIR);view.records.append((path,stamp(info)))
        _,includes=ini_selectors(view.file(PREFIX+'fpm/php.ini',131072))
        if includes:raise Rejected('PRE_ENTRY_SELECTION_REFUSED')
        for name in view.directory(PREFIX+'fpm/conf.d',32):
            if not name.endswith('.ini'):raise Rejected('PRE_ENTRY_SELECTION_REFUSED')
            _,includes=ini_selectors(view.ini_link(name))
            if includes:raise Rejected('PRE_ENTRY_CONFIG_REFUSED')
        _,includes=ini_selectors(view.file(PREFIX+'fpm/php-fpm.conf',16384),pool=True)
        if includes!=['/etc/php/7.4/fpm/pool.d/*.conf']:raise Rejected('PRE_ENTRY_SELECTION_REFUSED')
        pools=view.directory(PREFIX+'fpm/pool.d',8)
        if not pools:raise Rejected('PRE_ENTRY_SELECTION_REFUSED')
        for name in pools:
            if not name.endswith('.conf'):raise Rejected('PRE_ENTRY_SELECTION_REFUSED')
            _,includes=ini_selectors(view.file(PREFIX+'fpm/pool.d/'+name,16384),pool=True)
            if includes:raise Rejected('PRE_ENTRY_SELECTION_REFUSED')
        launch(unit_text(ns,deadline),master)
        if ns['_php_endpoint_identity'](master,deadline)!=snapshot[1]:raise Rejected('PRE_ENTRY_CHANGED')
        return tuple(view.records)
    finally:os.close(root)
