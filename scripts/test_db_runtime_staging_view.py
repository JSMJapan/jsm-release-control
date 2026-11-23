"""Verify the fresh root-created PHP package through the stable FPM root.

Freshness is produced by the reviewed capsule's mkdir(O_EXCL semantics), not
inferred from an inode alone. This consumer accepts no workflow script path.
"""
from contextlib import ExitStack
import hashlib
import os
import stat
from test_db_runtime_protocol import Rejected
from test_db_runtime_control_contract import PHP_FILES, staging_valid


def stamp(info):
    return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,info.st_nlink,
            info.st_size,info.st_mtime_ns,info.st_ctime_ns)


def root_owned(info,kind):
    return info.st_uid==0 and not info.st_mode&0o022 and stat.S_IFMT(info.st_mode)==kind


def verify(staging,kernel,snapshot):
    try:return _verify(staging,kernel,snapshot)
    except OSError:raise Rejected('STAGING_VIEW_REFUSED') from None


def _verify(staging,kernel,snapshot):
    if not staging_valid(staging) or sum(row['size'] for row in staging['files'].values())>256*1024:
        raise Rejected('STAGING_VIEW_REFUSED')
    deadline=kernel.deadline;ns=kernel.ns
    with ExitStack() as stack:
        root=ns['_manifest_root'](snapshot,snapshot[3][0][0],deadline);stack.callback(os.close,root)
        parent=root
        for part in staging['path'][1:].split('/'):
            kernel.check();fd=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
            stack.callback(os.close,fd)
            if not root_owned(os.fstat(fd),stat.S_IFDIR):raise Rejected('STAGING_VIEW_REFUSED')
            parent=fd
        directory=os.fstat(parent)
        if (directory.st_dev,directory.st_ino)!=(staging['device'],staging['inode']):raise Rejected('STAGING_VIEW_REFUSED')
        try:os.stat('.user.ini',dir_fd=parent,follow_symlinks=False)
        except FileNotFoundError:pass
        else:raise Rejected('STAGING_VIEW_REFUSED')
        records=[]
        for name in PHP_FILES:
            kernel.check();expected=staging['files'][name]
            fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent);stack.callback(os.close,fd)
            first=os.fstat(fd)
            if (not root_owned(first,stat.S_IFREG) or first.st_nlink!=1
                    or (first.st_dev,first.st_ino,first.st_size)!=(expected['device'],expected['inode'],expected['size'])):
                raise Rejected('STAGING_VIEW_REFUSED')
            digest=hashlib.sha256();total=0
            while True:
                kernel.check();part=os.read(fd,min(8192,expected['size']+1-total))
                if not part:break
                total+=len(part)
                if total>expected['size']:raise Rejected('STAGING_VIEW_REFUSED')
                digest.update(part)
            if (total!=expected['size'] or digest.hexdigest()!=expected['sha256']
                    or stamp(first)!=stamp(os.fstat(fd))
                    or stamp(first)!=stamp(os.stat(name,dir_fd=parent,follow_symlinks=False))):
                raise Rejected('STAGING_VIEW_REFUSED')
            records.append((name,stamp(first),digest.digest()))
        kernel.check()
        if stamp(directory)!=stamp(os.fstat(parent)):raise Rejected('STAGING_VIEW_REFUSED')
        return (directory.st_dev,directory.st_ino,tuple(records))
