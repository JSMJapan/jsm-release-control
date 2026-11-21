"""Fixed passive Docker summary, not a database or trusted-target admission.

Only this definition capsule crosses the existing protected TEST transport.
Summary Command/Labels/Mounts may exist in bounded private parser memory; no
raw summary, reference, path, name or exception is returned by these helpers.
"""

ERRORS = ('NONE', 'NOT_ATTEMPTED', 'UNIT_UNAVAILABLE', 'PATH_REFUSED',
    'PEER_REFUSED', 'UNSUPPORTED', 'DEADLINE', 'HTTP_REFUSED', 'HEADER_LIMIT',
    'BODY_LIMIT', 'SCHEMA_REFUSED', 'LIMIT_EXCEEDED', 'SOCKET_CHANGED',
    'DAEMON_CHANGED', 'OS_REFUSED')

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
        if public is not None and (type(public)is not int or not 1<=public<=65535):return unknown
        address=port.get('IP')
        if public is not None:
            if type(address)is not str or len(address)>64:return unknown
            try:loopback=ipaddress.ip_address(address).is_loopback
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
'''
