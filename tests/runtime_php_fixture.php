<?php
declare(strict_types=1);
namespace JsmTestDbRuntime2760;
require __DIR__.'/../scripts/test_db_runtime_probe.php';
require __DIR__.'/../scripts/test_db_runtime_startup.php';
require __DIR__.'/../scripts/test_db_runtime_pdo.php';
require __DIR__.'/../scripts/test_db_runtime_php_channel.php';
function check($value): void { if ($value!==true) { throw new \RuntimeException('FIXTURE_FAILED'); } }
function rejected(callable $test): void { try { $test(); } catch (\Throwable $e) { return; } throw new \RuntimeException('EXPECTED_REFUSAL'); }

foreach (["<?php return ['x'=>[true,false,null,1,1.2,-1,__DIR__. '/test']];", "<?php return ['x'=>dirname(dirname(__DIR__)), 'y'=>YII_DEBUG ? 3 : 0];"] as $raw) { configShape($raw); }
foreach (["<?php file_put_contents('PRIVATE','x'); return [];", "<?php return ['x'=>getenv('PRIVATE')];", "<?php return ['x'=>new PDO('PRIVATE')];", "<?php return []; echo 'PRIVATE';", "<?php return ['x'=>function(){}];", "<?php return ['x'=>\$secret];"] as $raw) { rejected(static function() use ($raw) { configShape($raw); }); }
generatedConfig('<?php $vendorDir = dirname(__DIR__); $baseDir = dirname($vendorDir); return ["x"=>$vendorDir."/x"];','/srv/app');
generatedConfig('<?php return [];','/srv/app');
$stamp=['dev'=>1,'ino'=>2,'mode'=>3,'uid'=>4,'gid'=>5,'nlink'=>1,'size'=>6,'mtime'=>7,'ctime'=>8,'atime'=>9];
check(fileStamp($stamp)===fileStamp(array_merge($stamp,['atime'=>100])));
rejected(static function() {generatedConfig('<?php $vendorDir=unknown(); return [];','/srv/app');});
$definition=nativeDefinition('mysql:host=127.0.0.1;dbname=stand','synthetic','not-a-secret',[]);
check($definition['target']['port']===3306);
foreach ([['mysql:host=localhost;dbname=stand',[]],['mysql:host=127.0.0.1;dbname=stand;unix_socket=/tmp/x',[]],['mysql:host=127.0.0.1;dbname=stand',[\PDO::ATTR_PERSISTENT=>true]],['mysql:host=127.0.0.1;dbname=stand',[\PDO::ATTR_AUTOCOMMIT=>false]],['mysql:host=127.0.0.1;dbname=stand',[1002=>'PRIVATE']]] as $case) {
    rejected(static function() use ($case) { nativeDefinition($case[0],'u','synthetic',$case[1]); });
}
applicationShape(['bootstrap'=>['log'],'components'=>['db'=>['class'=>'yii\\db\\Connection']]],[]);
foreach ([['bootstrap'=>['unknown']],['bootstrap'=>['log'],'on beforeRequest'=>'PRIVATE'],['bootstrap'=>['log'],'components'=>['db'=>['class'=>'unknown']]],['bootstrap'=>['log'],'components'=>['db'=>['on afterOpen'=>'PRIVATE']]]] as $config) { rejected(static function() use ($config) { applicationShape($config,[]); }); }
final class FakeWire {
    public $sent=[]; public $answers; public function __construct(array $a) {$this->answers=$a;}
    public function send($role,$seq,$payload) { $this->sent[]=$payload['stage']; }
    public function receive($role,$seq) { if (!array_key_exists($seq,$this->answers)) { throw new \RuntimeException('FRAME_REFUSED'); } return $this->answers[$seq]; }
}
foreach (['OK','STARTUP','ABORT_OPEN','ABORT_SELECT','BAD_ACK','NONCE'] as $mode) {
    $counts=['open'=>0,'select'=>0];
    $answers=[0=>['stage'=>'HELLO','publisher_uid'=>1000],2=>['stage'=>'OPEN'],4=>['stage'=>'SELECT'],6=>['stage'=>'RESULT','accepted'=>true]];
    if ($mode==='ABORT_OPEN') {$answers[2]=['stage'=>'ABORT'];}
    if ($mode==='ABORT_SELECT') {$answers[4]=['stage'=>'ABORT'];}
    if ($mode==='BAD_ACK') {$answers[6]['accepted']=false;}
    if ($mode==='NONCE') {unset($answers[0]);}
    $wire=new FakeWire($answers);
    $run=static function() use ($wire,$mode,$definition,&$counts) {
        phpDialogue($wire,static function($uid) use ($mode,$definition) { if ($mode==='STARTUP') { refuse('STARTUP_REFUSED'); } return $definition; },
            static function($d) use (&$counts) {++$counts['open']; return new \stdClass();},
            static function($pdo,$schema) use (&$counts) {++$counts['select']; return ['stage'=>'RESULT'];});
    };
    if ($mode==='OK') {$run();} else {rejected($run);}
    check($counts['open']===(in_array($mode,['STARTUP','ABORT_OPEN','NONCE'],true)?0:1));
    check($counts['select']===(in_array($mode,['OK','BAD_ACK'],true)?1:0));
}
$nonce=str_repeat('a',32);$digest=str_repeat('b',64);
foreach ([['ROOT',0,['stage'=>'HELLO','publisher_uid'=>1000]],['PHP',1,['stage'=>'TARGET','host'=>'127.0.0.1','port'=>3306,'schema'=>'stand','same_db'=>true]],['ROOT',6,['stage'=>'RESULT','accepted'=>true]]] as $case) {
    $raw=frame($nonce,$digest,$case[0],$case[1],$case[2]); check(unframe($raw,$nonce,$digest,$case[0],$case[1])===$case[2]);
}
rejected(static function() use ($nonce,$digest) {frame($nonce,$digest,'ROOT',2,['stage'=>'OPEN','private'=>[]]);});
echo "NATIVE_PHP_FIXTURES_PASS\n";
