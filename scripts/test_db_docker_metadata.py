"""Fixed passive Docker summary, not a database or trusted-target admission.

Only this definition capsule crosses the existing protected TEST transport.
Summary Command/Labels/Mounts may exist in bounded private parser memory; no
raw summary, reference, path, name or exception is returned by these helpers.
"""

import re

ERRORS = ('NONE', 'NOT_ATTEMPTED', 'UNIT_UNAVAILABLE', 'PATH_REFUSED',
    'PEER_REFUSED', 'UNSUPPORTED', 'DEADLINE', 'HTTP_REFUSED', 'HEADER_LIMIT',
    'BODY_LIMIT', 'SCHEMA_REFUSED', 'LIMIT_EXCEEDED', 'SOCKET_CHANGED',
    'DAEMON_CHANGED', 'OS_REFUSED', 'SUMMARY_UNKNOWN')

LIBRARY = 'DOCKER_ERRORS='+repr(ERRORS)+'\n'+r'''
import ipaddress,json,re,socket,struct,time
class DockerRefused(ValueError):
    def __init__(self,code):
        self.code=code if type(code)is str and code in DOCKER_ERRORS else 'SCHEMA_REFUSED'
        super().__init__(self.code)
def _docker_remaining(deadline):
    remaining=deadline-time.monotonic()
    if remaining<=0:raise DockerRefused('DEADLINE')
    return min(.75,remaining)
def _docker_pairs(items):
    result={}
    for key,value in items:
        if key in result:raise DockerRefused('SCHEMA_REFUSED')
        result[key]=value
    return result
def _docker_constant(_):raise DockerRefused('SCHEMA_REFUSED')
def _docker_ports(value):
    unknown={k:None for k in ('port3306_exposed','port3306_published','port3306_loopback','port3306_nonloopback')}
    result={k:False for k in unknown}
    if type(value)is not list or len(value)>64:return unknown
    for port in value:
        if (type(port)is not dict or not {'PrivatePort','Type'}<=set(port)
                or not set(port)<={'PrivatePort','PublicPort','IP','Type'}
                or type(port['PrivatePort'])is not int or not 1<=port['PrivatePort']<=65535
                or port['Type'] not in ('tcp','udp','sctp')):return unknown
        public=port.get('PublicPort')
        if 'PublicPort' in port and (type(public)is not int or not 1<=public<=65535):return unknown
        address=port.get('IP')
        if 'IP' in port and type(address)is not str:return unknown
        if public is not None:
            if type(address)is not str or len(address)>64:return unknown
            try:
                parsed=ipaddress.ip_address(address);mapped=getattr(parsed,'ipv4_mapped',None)
                loopback=parsed.is_loopback or mapped is not None and mapped.is_loopback
            except ValueError:return unknown
        elif address not in (None,''):return unknown
        if port['PrivatePort']!=3306 or port['Type']!='tcp':continue
        result['port3306_exposed']=True
        if public is not None:
            result['port3306_published']=True
            result['port3306_loopback' if loopback else 'port3306_nonloopback']=True
    return result
def _docker_parse_body(body):
    if type(body)is not bytes or len(body)>65536:raise DockerRefused('BODY_LIMIT')
    try:
        rows=json.loads(body.decode('utf-8'),object_pairs_hook=_docker_pairs,parse_constant=_docker_constant)
    except (ValueError,UnicodeError,RecursionError):raise DockerRefused('SCHEMA_REFUSED') from None
    if type(rows)is not list:raise DockerRefused('SCHEMA_REFUSED')
    if len(rows)>8:raise DockerRefused('LIMIT_EXCEEDED')
    result=[];identities=set()
    for item in rows:
        if type(item)is not dict:raise DockerRefused('SCHEMA_REFUSED')
        identity=item.get('Id')
        if type(identity)is not str or not re.fullmatch('[0-9a-f]{64}',identity) or identity in identities:raise DockerRefused('SCHEMA_REFUSED')
        identities.add(identity)
        image=item.get('Image');family='unknown'
        if type(image)is str and 0<len(image)<=512:
            match=re.fullmatch(r'(?:docker\.io/(?:library/)?)?(mysql|mariadb)(?::[A-Za-z0-9_.-]+)?(?:@sha256:[0-9a-f]{64})?',image)
            family=match[1] if match else 'other'
        image_id=item.get('ImageID')
        if type(image_id)is not str or not re.fullmatch('sha256:[0-9a-f]{64}',image_id):image_id=None
        result.append(dict(id=identity,image_id=image_id,image_family=family,**_docker_ports(item.get('Ports'))))
    return result
def _docker_http_headers(data):
    try:lines=data.decode('ascii').split('\r\n')
    except UnicodeError:raise DockerRefused('HTTP_REFUSED') from None
    if not lines or not re.fullmatch(r'HTTP/1\.[01] 200(?: [\x20-\x7e]*)?',lines[0]):raise DockerRefused('HTTP_REFUSED')
    headers={}
    for line in lines[1:]:
        name,sep,value=line.partition(':');name=name.lower()
        if (not sep or not re.fullmatch('[a-z0-9-]+',name) or name in headers
                or any(ord(c)<32 and c!='\t' or ord(c)>126 for c in value)):raise DockerRefused('HTTP_REFUSED')
        headers[name]=value.strip()
    if ('transfer-encoding' in headers or headers.get('content-type','').lower().split(';')[0].strip()!='application/json'):raise DockerRefused('HTTP_REFUSED')
    length=headers.get('content-length')
    if length is not None:
        if not re.fullmatch('[0-9]{1,10}',length):raise DockerRefused('HTTP_REFUSED')
        length=int(length)
        if length>65536:raise DockerRefused('BODY_LIMIT')
    return length
def _docker_http_response(connection,deadline):
    data=bytearray();header_end=None;length=None
    while True:
        connection.settimeout(_docker_remaining(deadline))
        chunk=connection.recv(min(4096,8192+65536+1-len(data)))
        if not chunk:break
        data.extend(chunk)
        if header_end is None:
            separator=data.find(b'\r\n\r\n')
            if separator>=0:
                header_end=separator+4
                if header_end>8192:raise DockerRefused('HEADER_LIMIT')
                length=_docker_http_headers(bytes(data[:separator]))
            elif len(data)>8192:raise DockerRefused('HEADER_LIMIT')
        if header_end is not None and len(data)-header_end>65536:raise DockerRefused('BODY_LIMIT')
    _docker_remaining(deadline)
    if header_end is None:raise DockerRefused('HTTP_REFUSED')
    body=bytes(data[header_end:])
    if length is not None and len(body)!=length:raise DockerRefused('HTTP_REFUSED')
    return body
def _docker_packet(error='NOT_ATTEMPTED',attempted=False,containers=None):
    return dict(state='OBSERVED' if error=='NONE' else 'INCOMPLETE' if error in ('LIMIT_EXCEEDED','SUMMARY_UNKNOWN') else 'UNKNOWN',
        attempted=attempted,error=error,containers=[] if containers is None else containers)
def _docker_socket_metadata(deadline):
    fds=[]
    try:
        _docker_remaining(deadline);fds,name=_parents('/run/docker.sock',deadline)
        for fd in fds:
            _docker_remaining(deadline);parent=os.fstat(fd)
            if not stat.S_ISDIR(parent.st_mode) or parent.st_uid!=0 or parent.st_mode&0o022:raise DockerRefused('PATH_REFUSED')
        _docker_remaining(deadline);before=os.stat(name,dir_fd=fds[-1],follow_symlinks=False)
        # root:docker 0660 is supported; world-writable sockets are refused.
        if not stat.S_ISSOCK(before.st_mode) or before.st_uid!=0 or before.st_mode&0o002 or before.st_nlink!=1:raise DockerRefused('PATH_REFUSED')
        _docker_remaining(deadline)
        if _stamp(before)!=_stamp(os.stat(name,dir_fd=fds[-1],follow_symlinks=False)):raise DockerRefused('SOCKET_CHANGED')
        return _stamp(before)
    except OSError:raise DockerRefused('PATH_REFUSED') from None
    finally:
        for fd in reversed(fds):os.close(fd)
def _docker_unit_ready(unit):
    return (type(unit)is dict and set(unit)=={'load','active','pid'} and unit['load']=='loaded'
        and unit['active']=='active' and _pid_ready(unit['pid']))
def _docker_begin(unit,deadline):
    attempted=False;connection=None;verified=False;identity=None
    def refused(code):
        result=dict(public=_docker_packet(code,attempted))
        if attempted and verified:result.update(unit=dict(unit),identity=identity)
        return result
    try:
        until=min(deadline,time.monotonic()+.75);_docker_remaining(until)
        if not _docker_unit_ready(unit):raise DockerRefused('UNIT_UNAVAILABLE')
        if not hasattr(socket,'SO_PEERCRED'):raise DockerRefused('UNSUPPORTED')
        identity=_docker_socket_metadata(until)
        _docker_remaining(until);connection=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        connection.settimeout(_docker_remaining(until));connection.connect('/run/docker.sock')
        _docker_remaining(until)
        credentials=connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,struct.calcsize('iII'))
        if type(credentials)is not bytes or len(credentials)!=struct.calcsize('iII'):raise DockerRefused('PEER_REFUSED')
        pid,uid,_=struct.unpack('iII',credentials)
        # Socket-activated/inherited listener PID1 is intentionally unsupported.
        if uid!=0 or pid!=unit['pid']:raise DockerRefused('PEER_REFUSED')
        if identity!=_docker_socket_metadata(until):raise DockerRefused('SOCKET_CHANGED')
        verified=True
        connection.settimeout(_docker_remaining(until));attempted=True
        connection.sendall(b'GET /containers/json?all=1&size=0&limit=9 HTTP/1.0\r\nHost: docker\r\nConnection: close\r\n\r\n')
        body=_docker_http_response(connection,until);rows=_docker_parse_body(body);_docker_remaining(until)
        complete=all(row['image_id']is not None and row['image_family']!='unknown'
            and all(type(row[k])is bool for k in ('port3306_exposed','port3306_published','port3306_loopback','port3306_nonloopback')) for row in rows)
        return dict(public=_docker_packet('NONE' if complete else 'SUMMARY_UNKNOWN',True,rows),unit=dict(unit),identity=identity)
    except DockerRefused as error:return refused(error.code)
    except (socket.timeout,TimeoutError):return refused('DEADLINE')
    except Exception as error:
        return refused('DEADLINE' if getattr(error,'code',None)=='DEADLINE' else 'OS_REFUSED')
    finally:
        if connection is not None:
            try:connection.close()
            except OSError:pass
def _docker_finish(pending,unit,deadline):
    if 'unit' not in pending:return pending['public']
    try:
        _docker_remaining(deadline)
        if not _docker_unit_ready(unit) or pending['unit']!=unit:raise DockerRefused('DAEMON_CHANGED')
        if pending['identity']!=_docker_socket_metadata(deadline):raise DockerRefused('SOCKET_CHANGED')
        _docker_remaining(deadline)
        return pending['public']
    except DockerRefused as error:return _docker_packet(error.code,pending['public']['attempted'])
    except Exception as error:
        return _docker_packet('DEADLINE' if getattr(error,'code',None)=='DEADLINE' else 'OS_REFUSED',pending['public']['attempted'])
'''


def project_discovery(value):
    """Accept only the bounded public result, never raw Docker summary fields."""
    if (type(value) is not dict or set(value) != {'state','attempted','error','containers'}
            or value['state'] not in ('OBSERVED','UNKNOWN','INCOMPLETE')
            or type(value['attempted']) is not bool or type(value['error']) is not str
            or value['error'] not in ERRORS or type(value['containers']) is not list
            or len(value['containers']) > 8):
        return None
    expected = ('OBSERVED' if value['error']=='NONE' else
        'INCOMPLETE' if value['error'] in ('LIMIT_EXCEEDED','SUMMARY_UNKNOWN') else 'UNKNOWN')
    if value['state'] != expected or (value['state'] != 'UNKNOWN' and not value['attempted']):
        return None
    if value['state']=='UNKNOWN' and value['containers']:
        return None
    if value['error']=='LIMIT_EXCEEDED' and value['containers']:
        return None
    identities=set(); booleans=('port3306_exposed','port3306_published','port3306_loopback','port3306_nonloopback')
    for row in value['containers']:
        if (type(row) is not dict or set(row) != {'id','image_id','image_family',*booleans}
                or type(row['id']) is not str or not re.fullmatch('[0-9a-f]{64}',row['id']) or row['id'] in identities
                or (row['image_id'] is not None and (type(row['image_id']) is not str or not re.fullmatch('sha256:[0-9a-f]{64}',row['image_id'])))
                or row['image_family'] not in ('mysql','mariadb','other','unknown')
                or any(row[k] is not None and type(row[k]) is not bool for k in booleans)):
            return None
        identities.add(row['id'])
        if any(row[k] is None for k in booleans):
            if not all(row[k] is None for k in booleans): return None
        elif (row['port3306_published'] and not row['port3306_exposed']
                or (row['port3306_loopback'] or row['port3306_nonloopback']) != row['port3306_published']):
            return None
        if value['state']=='OBSERVED' and (row['image_id'] is None or row['image_family']=='unknown'
                or any(row[k] is None for k in booleans)):
            return None
    return value
