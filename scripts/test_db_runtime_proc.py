"""Only verified target PID tcp/tcp6: proc-net pathname ctime re-instantiates.

The held FD retains the complete original stamp. All remaining path identity
attributes and both process identities remain mandatory. Existing readers are
unchanged. Data stays private in the producer.
"""
import os
import stat
from test_db_runtime_protocol import Rejected


def read_tcp(pid, suffix, deadline, ns, identity):
    if type(pid) is not int or not 1<pid<=2147483647 or suffix not in ('tcp','tcp6'):
        raise Rejected('PROCESS_REFUSED')
    before_process=identity()
    path='/proc/'+str(pid)+'/net/'+suffix
    fds=[];fd=None
    try:
        fds,name=ns['_parents'](path,deadline)
        ns['_check'](deadline)
        fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=fds[-1])
        before=os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1:raise Rejected('TCP_REFUSED')
        data=bytearray()
        while True:
            ns['_check'](deadline)
            chunk=os.read(fd,min(4096,65537-len(data)))
            if not chunk:break
            data.extend(chunk)
            if len(data)>65536:raise Rejected('TCP_REFUSED')
        held=ns['_stamp'](before)
        if held!=ns['_stamp'](os.fstat(fd)):raise Rejected('PEER_CHANGED')
        last=ns['_stamp'](os.stat(name,dir_fd=fds[-1],follow_symlinks=False))
        if held[:-1]!=last[:-1] or identity()!=before_process:raise Rejected('PEER_CHANGED')
        ns['_check'](deadline)
        return data.decode('ascii')
    finally:
        if fd is not None:os.close(fd)
        for parent in reversed(fds):os.close(parent)
