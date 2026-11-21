"""Code-owned systemd socket association; no discovery, configuration or SQL.

This capsule augments the existing single-connection Docker branch only when
requested by the fixed protected entry. Raw proc and unit data remain private.
"""

REASONS=('NONE','NOT_ATTEMPTED','PEER_SCHEMA_REFUSED','PEER_UID_REFUSED','PEER_PID_REFUSED',
    'UNIT_RELATION_REFUSED','PROCESS_REFUSED','NAMESPACE_REFUSED','FD_REFUSED',
    'LISTENER_REFUSED','BINDING_CHANGED','SOCKET_CHANGED','DAEMON_CHANGED',
    'DEADLINE','OS_REFUSED','PROC_REFUSED','UNIT_UNAVAILABLE','PATH_REFUSED','UNSUPPORTED',
    'UNIT_QUERY_REFUSED','UNIT_SCHEMA_REFUSED','SOCKET_STATE_REFUSED','SERVICE_STATE_REFUSED',
    'SOCKET_ACCEPT_REFUSED','SOCKET_LISTEN_REFUSED','SOCKET_TRIGGER_REFUSED',
    'SERVICE_TRIGGER_REFUSED','SERVICE_PROPERTIES_REFUSED')
BOOLEANS=('peer_root','unit_relation','init_expected','docker_expected','namespaces_match',
    'listener_unique','init_has_listener','docker_has_listener','before_proved','after_stable')

LIBRARY='BINDING_REASONS='+repr(REASONS)+'\nBINDING_BOOLEANS='+repr(BOOLEANS)+'\n'+r'''
class BindingRefused(DockerRefused):
    def __init__(self,reason):
        self.reason=reason if type(reason)is str and reason in BINDING_REASONS else 'OS_REFUSED'
        super().__init__('PEER_REFUSED')
def _binding_units(text):
    if type(text)is not str or len(text.encode('utf-8'))>4096:raise BindingRefused('UNIT_SCHEMA_REFUSED')
    result={};allowed={'Id','LoadState','ActiveState','SubState','Accept','Listen','Triggers','TriggeredBy'}
    for block in text.strip().split('\n\n'):
        values={}
        for line in block.splitlines():
            key,sep,value=line.partition('=')
            if not sep or key not in allowed or key in values:raise BindingRefused('UNIT_SCHEMA_REFUSED')
            values[key]=value
        role={'docker.socket':'socket','docker.service':'docker'}.get(values.get('Id'))
        if role is None or role in result:raise BindingRefused('UNIT_SCHEMA_REFUSED')
        required={'Id','LoadState','ActiveState','SubState'}|({'Accept','Listen','Triggers'} if role=='socket' else {'TriggeredBy'})
        if not required<=set(values):raise BindingRefused('UNIT_SCHEMA_REFUSED')
        if values['LoadState']!='loaded' or values['ActiveState']!='active':raise BindingRefused('SOCKET_STATE_REFUSED' if role=='socket' else 'SERVICE_STATE_REFUSED')
        if role=='socket':
            if values['SubState'] not in ('listening','running'):raise BindingRefused('SOCKET_STATE_REFUSED')
            if values['Accept']!='no':raise BindingRefused('SOCKET_ACCEPT_REFUSED')
            if values['Listen']!='/run/docker.sock (Stream)':raise BindingRefused('SOCKET_LISTEN_REFUSED')
            if values['Triggers']!='docker.service' or values.get('TriggeredBy','')!='':raise BindingRefused('SOCKET_TRIGGER_REFUSED')
        else:
            if values['SubState']!='running':raise BindingRefused('SERVICE_STATE_REFUSED')
            if values['TriggeredBy']!='docker.socket':raise BindingRefused('SERVICE_TRIGGER_REFUSED')
            if any(values.get(k,'')!='' for k in ('Accept','Listen','Triggers')):raise BindingRefused('SERVICE_PROPERTIES_REFUSED')
        result[role]=values
    if set(result)!={'socket','docker'}:raise BindingRefused('UNIT_SCHEMA_REFUSED')
    return result
def _binding_listener(text):
    if type(text)is not str or len(text.encode('utf-8'))>65536:raise BindingRefused('PROC_REFUSED')
    lines=text.splitlines();found=[]
    if not lines or lines[0].split()!=['Num','RefCount','Protocol','Flags','Type','St','Inode','Path']:raise BindingRefused('LISTENER_REFUSED')
    for line in lines[1:]:
        fields=line.split(None,7)
        if len(fields)<7:raise BindingRefused('LISTENER_REFUSED')
        if len(fields)==7 or fields[7]!='/run/docker.sock':continue
        if (not re.fullmatch('[0-9a-fA-F]+:',fields[0]) or any(not re.fullmatch('[0-9a-fA-F]{8}',fields[i]) for i in (1,2,3))
                or fields[2]!='00000000' or fields[4]!='0001' or fields[5] not in ('01','02','03','04')
                or not re.fullmatch('[1-9][0-9]{0,19}',fields[6])):raise BindingRefused('LISTENER_REFUSED')
        if fields[3]=='00010000':
            if fields[5]!='01':raise BindingRefused('LISTENER_REFUSED')
            found.append(int(fields[6]))
        elif fields[3]!='00000000':raise BindingRefused('LISTENER_REFUSED')
    if len(found)!=1:raise BindingRefused('LISTENER_REFUSED')
    return found[0]
def _binding_new():
    return dict(public=dict(mode='NONE',state='SKIPPED',peer_kind='UNKNOWN',reason='NOT_ATTEMPTED',
        **{key:None for key in BINDING_BOOLEANS}))
def _binding_refused(info,reason,after=False):
    reason=reason if type(reason)is str and reason in BINDING_REASONS else 'OS_REFUSED'
    state='SKIPPED' if info['public']['state']=='SKIPPED' and reason!='PEER_SCHEMA_REFUSED' else 'UNKNOWN'
    info['public'].update(state=state,reason=reason)
    if after and reason in ('BINDING_CHANGED','SOCKET_CHANGED','DAEMON_CHANGED'):info['public']['after_stable']=False
def _binding_identity(role,pid,deadline,axes):
    if role not in ('init','docker') or not _pid_ready(pid) or role=='init' and pid!=1:raise BindingRefused('PROCESS_REFUSED')
    _docker_remaining(deadline);prefix='/proc/'+str(pid);own='/proc/'+str(os.getpid())
    start=_proc_start(_proc_read(prefix+'/stat',deadline,4096),pid)
    exe=_readlink(prefix+'/exe',deadline)
    expected={'init':('/lib/systemd/systemd','/usr/lib/systemd/systemd'),'docker':('/usr/bin/dockerd',)}
    axes[role+'_expected']=exe in expected[role]
    if not axes[role+'_expected']:raise BindingRefused('PROCESS_REFUSED')
    namespaces=[]
    for kind in ('net','mnt','pid'):
        _docker_remaining(deadline);observed=_readlink(prefix+'/ns/'+kind,deadline);observer=_readlink(own+'/ns/'+kind,deadline)
        if not re.fullmatch(kind+r':\[[0-9]{1,20}\]',observed) or not re.fullmatch(kind+r':\[[0-9]{1,20}\]',observer):raise BindingRefused('NAMESPACE_REFUSED')
        if observed!=observer:
            axes['namespaces_match']=False;raise BindingRefused('NAMESPACE_REFUSED')
        namespaces.append(observed)
    return dict(start=start,exe=exe,namespaces=tuple(namespaces))
def _binding_process(role,pid,deadline,axes):
    identity=_binding_identity(role,pid,deadline,axes)
    try:
        _docker_remaining(deadline);sockets=_fd_sockets(pid,deadline)
    except Exception as error:
        raise BindingRefused('DEADLINE' if getattr(error,'code',None)=='DEADLINE' else 'FD_REFUSED') from None
    if identity!=_binding_identity(role,pid,deadline,axes):raise BindingRefused('BINDING_CHANGED')
    return identity,sockets
def _binding_snapshot(unit,deadline,axes):
    stage='UNIT_QUERY_REFUSED'
    try:
        _docker_remaining(deadline)
        properties=('Id','LoadState','ActiveState','SubState','Accept','Listen','Triggers','TriggeredBy')
        text=_systemctl_snapshot(properties,('docker.socket','docker.service'),deadline)
        stage='UNIT_SCHEMA_REFUSED';units=_binding_units(text)
        axes['unit_relation']=True
        stage='PROC_REFUSED';_docker_remaining(deadline)
        inode=_binding_listener(_proc_read('/proc/'+str(os.getpid())+'/net/unix',deadline))
        axes['listener_unique']=True
        stage='PROCESS_REFUSED';init,init_fds=_binding_process('init',1,deadline,axes)
        docker,docker_fds=_binding_process('docker',unit['pid'],deadline,axes)
        axes['namespaces_match']=True
        axes['init_has_listener']=inode in init_fds;axes['docker_has_listener']=inode in docker_fds
        if not axes['init_has_listener'] or not axes['docker_has_listener']:raise BindingRefused('FD_REFUSED')
        _docker_remaining(deadline);identity=_docker_socket_metadata(deadline)
        return dict(units=units,init=init,docker=docker,listener=inode,socket=identity)
    except BindingRefused:raise
    except Exception as error:
        raise BindingRefused('DEADLINE' if getattr(error,'code',None)=='DEADLINE' else stage) from None
def _binding_before(info,pid,uid,unit,identity,deadline):
    public=info['public'];public.update(state='UNKNOWN',reason='NONE',peer_root=uid==0,
        peer_kind='MAINPID' if pid==unit['pid'] else 'PID1' if pid==1 else 'OTHER')
    if uid!=0:raise BindingRefused('PEER_UID_REFUSED')
    if pid==unit['pid']:
        public['mode']='MAINPID';return
    if pid!=1:raise BindingRefused('PEER_PID_REFUSED')
    public['mode']='SYSTEMD'
    snapshot=_binding_snapshot(unit,deadline,public)
    if snapshot['socket']!=identity:raise BindingRefused('SOCKET_CHANGED')
    info['snapshot']=snapshot
def _binding_after(info,unit,deadline):
    if info['public']['mode']=='SYSTEMD':
        until=min(deadline,info['until']);_docker_remaining(until)
        axes={key:None for key in BINDING_BOOLEANS}
        if info['snapshot']!=_binding_snapshot(unit,until,axes):raise BindingRefused('BINDING_CHANGED')
        _docker_remaining(until)
    info['public'].update(state='PROVED',reason='NONE',after_stable=True)
def _binding_public(pending,packet):
    info=pending.get('binding',_binding_new());public=dict(info['public'])
    if public['state']=='UNKNOWN' and public['reason']=='NONE':
        public['reason']=packet['error'] if packet['error'] in BINDING_REASONS else 'OS_REFUSED'
    return public
'''


def project_binding(value,packet):
    """Closed pre/post diagnostics; never promote an observed ID to a target."""
    if (type(value) is not dict or set(value)!={'mode','state','peer_kind','reason',*BOOLEANS}
            or value['mode'] not in ('NONE','MAINPID','SYSTEMD')
            or value['state'] not in ('SKIPPED','UNKNOWN','PROVED')
            or value['peer_kind'] not in ('UNKNOWN','MAINPID','PID1','OTHER')
            or type(value['reason']) is not str or value['reason'] not in REASONS
            or any(value[key] is not None and type(value[key]) is not bool for key in BOOLEANS)
            or type(packet) is not dict or type(packet.get('attempted')) is not bool
            or type(packet.get('containers')) is not list):
        return None
    graph=tuple(key for key in BOOLEANS if key not in ('peer_root','before_proved','after_stable'))
    if value['state']=='SKIPPED':
        if (value['mode']!='NONE' or value['peer_kind']!='UNKNOWN' or any(value[k] is not None for k in BOOLEANS)
                or packet['attempted'] or packet['containers']):return None
    elif value['state']=='UNKNOWN' and value['reason'] in ('NONE','NOT_ATTEMPTED'):
        return None
    if value['before_proved'] is True:
        if value['peer_root'] is not True:return None
        if value['mode']=='MAINPID':
            if value['peer_kind']!='MAINPID' or any(value[k] is not None for k in graph):return None
        elif value['mode']=='SYSTEMD':
            if value['peer_kind']!='PID1' or any(value[k] is not True for k in graph):return None
        else:return None
    if packet['attempted'] and value['before_proved'] is not True:return None
    if value['after_stable'] is not None and not packet['attempted']:return None
    if value['state']=='PROVED':
        if value['reason']!='NONE' or value['before_proved'] is not True or value['after_stable'] is not True:return None
    elif value['after_stable'] is True:return None
    if (packet.get('state')=='OBSERVED' or packet['containers']) and value['state']!='PROVED':return None
    return value
