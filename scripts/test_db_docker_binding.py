"""Code-owned systemd socket association; no discovery, configuration or SQL.

This capsule augments the existing single-connection Docker branch only when
requested by the fixed protected entry. Raw proc and unit data remain private.
"""

REASONS=('NONE','NOT_ATTEMPTED','PEER_SCHEMA_REFUSED','PEER_UID_REFUSED','PEER_PID_REFUSED',
    'UNIT_RELATION_REFUSED','PROCESS_REFUSED','NAMESPACE_REFUSED','FD_REFUSED',
    'LISTENER_REFUSED','BINDING_CHANGED','SOCKET_CHANGED','DAEMON_CHANGED',
    'DEADLINE','OS_REFUSED','PROC_REFUSED')

LIBRARY='BINDING_REASONS='+repr(REASONS)+'\n'+r'''
class BindingRefused(DockerRefused):
    def __init__(self,reason):
        self.reason=reason if type(reason)is str and reason in BINDING_REASONS else 'OS_REFUSED'
        super().__init__('PEER_REFUSED')
def _binding_units(text):
    if type(text)is not str or len(text.encode('utf-8'))>4096:raise BindingRefused('UNIT_RELATION_REFUSED')
    result={};allowed={'Id','LoadState','ActiveState','SubState','Accept','Listen','Triggers','TriggeredBy'}
    for block in text.strip().split('\n\n'):
        values={}
        for line in block.splitlines():
            key,sep,value=line.partition('=')
            if not sep or key not in allowed or key in values:raise BindingRefused('UNIT_RELATION_REFUSED')
            values[key]=value
        role={'docker.socket':'socket','docker.service':'docker'}.get(values.get('Id'))
        if role is None or role in result:raise BindingRefused('UNIT_RELATION_REFUSED')
        required={'Id','LoadState','ActiveState','SubState'}|({'Accept','Listen','Triggers'} if role=='socket' else {'TriggeredBy'})
        if not required<=set(values) or values['LoadState']!='loaded' or values['ActiveState']!='active':raise BindingRefused('UNIT_RELATION_REFUSED')
        if role=='socket':
            if (values['SubState']!='listening' or values['Accept']!='no'
                    or values['Listen']!='/run/docker.sock (Stream)' or values['Triggers']!='docker.service'
                    or values.get('TriggeredBy','')!=''):raise BindingRefused('UNIT_RELATION_REFUSED')
        elif (values['SubState']!='running' or values['TriggeredBy']!='docker.socket'
                or any(values.get(k,'')!='' for k in ('Accept','Listen','Triggers'))):raise BindingRefused('UNIT_RELATION_REFUSED')
        result[role]=values
    if set(result)!={'socket','docker'}:raise BindingRefused('UNIT_RELATION_REFUSED')
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
                or fields[4]!='0001' or fields[5] not in ('01','02','03','04')
                or not re.fullmatch('[1-9][0-9]{0,19}',fields[6])):raise BindingRefused('LISTENER_REFUSED')
        if fields[3]=='00010000':
            if fields[5]!='01':raise BindingRefused('LISTENER_REFUSED')
            found.append(int(fields[6]))
        elif fields[3]!='00000000':raise BindingRefused('LISTENER_REFUSED')
    if len(found)!=1:raise BindingRefused('LISTENER_REFUSED')
    return found[0]
'''
