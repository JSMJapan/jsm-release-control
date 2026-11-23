<?php
declare(strict_types=1);
namespace JsmTestDbRuntime2760;

final class PrivateWire
{
    private $socket; private $nonce; private $digest; private $deadline;
    public function __construct($socket,string $nonce,string $digest,float $deadline)
    { $this->socket=$socket; $this->nonce=$nonce; $this->digest=$digest; $this->deadline=$deadline; }
    private function timeout(): void
    {
        $remaining=$this->deadline-hrtime(true)/1e9;
        if ($remaining<=0) { refuse('DEADLINE'); }
        $micros=(int)(min(0.75,$remaining)*1e6);
        foreach ([SO_RCVTIMEO,SO_SNDTIMEO] as $option) {
            if (!@socket_set_option($this->socket,SOL_SOCKET,$option,['sec'=>0,'usec'=>max(1,$micros)])) { refuse('CHANNEL_REFUSED'); }
        }
    }
    public function send(string $role,int $sequence,array $payload): void
    {
        $raw=frame($this->nonce,$this->digest,$role,$sequence,$payload); $at=0;
        while ($at<strlen($raw)) {
            $this->timeout(); $written=@socket_write($this->socket,substr($raw,$at));
            if (!is_int($written) || $written<1) { refuse('CHANNEL_REFUSED'); } $at+=$written;
        }
        $this->timeout();
    }
    public function receive(string $role,int $sequence): array
    {
        $raw='';
        while (substr($raw,-1)!=="\n") {
            $this->timeout(); $part=@socket_read($this->socket,min(1024,MAX_FRAME+1-strlen($raw)),PHP_BINARY_READ);
            if (!is_string($part) || $part==='' || strlen($raw)+strlen($part)>MAX_FRAME) { refuse('CHANNEL_REFUSED'); } $raw.=$part;
        }
        $this->timeout(); return unframe($raw,$this->nonce,$this->digest,$role,$sequence);
    }
}

function privateEntry(): void
{
    if (PHP_SAPI!=='fpm-fcgi' || ($_SERVER['JSM_DB_PROBE'] ?? null)!==VERSION
        || isset($_SERVER['HTTP_JSM_DB_PROBE']) || ($_SERVER['REQUEST_METHOD'] ?? null)!=='POST'
        || ($_SERVER['CONTENT_LENGTH'] ?? null)!=='0' || ($_SERVER['QUERY_STRING'] ?? null)!=='') { refuse('ENTRY_REFUSED'); }
    foreach (['JSM_DB_NONCE'=>32,'JSM_DB_CONTEXT'=>64,'JSM_DB_CHANNEL'=>32] as $name=>$size) {
        if (!is_string($_SERVER[$name] ?? null) || !preg_match('/\A[0-9a-f]{'.$size.'}\z/D',$_SERVER[$name])) { refuse('ENTRY_REFUSED'); }
    }
    if (!extension_loaded('sockets')) { refuse('CHANNEL_CAPABILITY_REFUSED'); }
    $socket=@socket_create(AF_UNIX,SOCK_STREAM,0);
    if ($socket===false) { refuse('CHANNEL_REFUSED'); }
    try {
        if (!@socket_set_option($socket,SOL_SOCKET,SO_SNDTIMEO,['sec'=>0,'usec'=>750000])
            || !@socket_connect($socket,"\0jsm-db-2760-".$_SERVER['JSM_DB_CHANNEL'])) { refuse('CHANNEL_REFUSED'); }
        $wire=new PrivateWire($socket,$_SERVER['JSM_DB_NONCE'],$_SERVER['JSM_DB_CONTEXT'],hrtime(true)/1e9+3);
        phpDialogue($wire,static function(int $uid) {  $app=configuredApplication($uid);loadModels($uid);return connectionDefinition($app); },
            __NAMESPACE__.'\\nativeConnect',__NAMESPACE__.'\\metadata');
    } finally { @socket_close($socket); }
}
