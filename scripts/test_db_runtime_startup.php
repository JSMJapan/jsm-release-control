<?php
declare(strict_types=1);
namespace JsmTestDbRuntime2760;

// This profile uses the existing installed vendor as a trust boundary. It
// validates executable config and startup hooks; it is not vendor attestation.
const APP_ROOT = '/srv/jsm/app/backend';
const MAIN_DEFINITION_SHA = '5e0f81775cf696d6376867b04c53b6927544c1adb9630db96aeb06c686a9ec8f';
const COMMON_BOOTSTRAP_SHA = '46c0ce237a1e424586426d0a02b8999649cf550475e6716e19e25f0208d5f514';
const EMPTY_BOOTSTRAP_SHA = '775fc33df0481713159236f2c706f7bdf1f37a19c5d65dae94068b723a5fca49';

function refuse(string $reason): void { throw new \RuntimeException($reason); }

function fileStamp(array $info): array
{
    $result=[]; foreach (['dev','ino','mode','uid','gid','nlink','size','mtime','ctime'] as $key) { $result[]=$info[$key]; } return $result;
}

function checkedFile(string $path, int $publisher, int $limit = 65536): string
{
    if ($path === '' || $path[0] !== '/' || strpos($path, '/..') !== false) { refuse('STARTUP_REFUSED'); }
    $part = '';
    foreach (explode('/', ltrim($path, '/')) as $index => $name) {
        $part .= '/'.$name; $info = @lstat($part);
        if ($info === false || !in_array($info['uid'], [0,$publisher], true) || ($info['mode'] & 0022)) { refuse('STARTUP_REFUSED'); }
        if ($part !== $path && ($info['mode'] & 0170000) !== 0040000) { refuse('STARTUP_REFUSED'); }
    }
    if (($info['mode'] & 0170000) !== 0100000 || $info['nlink'] !== 1 || $info['size'] > $limit) { refuse('STARTUP_REFUSED'); }
    $fd = @fopen($path, 'rb');
    if ($fd === false) { refuse('STARTUP_REFUSED'); }
    try {
        $before = fstat($fd); $raw = stream_get_contents($fd, $limit+1); $after = fstat($fd); clearstatcache(true,$path); $last = @lstat($path);
        if ($last===false || fileStamp($before)!==fileStamp($after) || fileStamp($before)!==fileStamp($info) || fileStamp($last)!==fileStamp($info) || !is_string($raw) || strlen($raw)>$limit) { refuse('STARTUP_REFUSED'); }
        return $raw;
    } finally { fclose($fd); }
}

final class LiteralConfig
{
    private $tokens; private $at = 0;
    public function __construct(string $raw)
    {
        if (strlen($raw)>65536) { refuse('CONFIG_SHAPE_REFUSED'); }
        $this->tokens = array_values(array_filter(token_get_all($raw), static function($t) {
            return !is_array($t) || !in_array($t[0],[T_OPEN_TAG,T_WHITESPACE,T_COMMENT,T_DOC_COMMENT],true);
        }));
    }
    private function token() { return $this->tokens[$this->at] ?? null; }
    private function take($kind): bool
    {
        $t=$this->token(); if ((is_array($t) ? $t[0] : $t) !== $kind) { return false; } ++$this->at; return true;
    }
    private function need($kind): void { if (!$this->take($kind)) { refuse('CONFIG_SHAPE_REFUSED'); } }
    private function atom(int $depth): void
    {
        if ($depth>16) { refuse('CONFIG_SHAPE_REFUSED'); }
        $t=$this->token();
        if ($this->take('[')) { $this->items(']',$depth+1); return; }
        if ($this->take(T_ARRAY)) { $this->need('('); $this->items(')',$depth+1); return; }
        if ($this->take('-')) { $this->need(T_LNUMBER); return; }
        foreach ([T_CONSTANT_ENCAPSED_STRING,T_LNUMBER,T_DNUMBER,T_DIR] as $kind) { if ($this->take($kind)) { return; } }
        if (is_array($t) && $t[0] === T_STRING) {
            ++$this->at;
            if (in_array(strtolower($t[1]),['true','false','null'],true)) { return; }
            if ($t[1] === 'YII_DEBUG') { return; }
            if ($t[1] === 'dirname') { $this->need('('); $this->atom($depth+1); $this->need(')'); return; }
            if (in_array($t[1],['PDO','NumberFormatter'],true) && $this->take(T_DOUBLE_COLON)) {
                $constant=$this->token();
                if (!is_array($constant) || $constant[0]!==T_STRING || !preg_match('/\A[A-Z][A-Z0-9_]{0,64}\z/D',$constant[1])) { refuse('CONFIG_SHAPE_REFUSED'); }
                ++$this->at; return;
            }
        }
        refuse('CONFIG_SHAPE_REFUSED');
    }
    private function expression(int $depth): void
    {
        $this->atom($depth);
        while ($this->take('.')) { $this->atom($depth+1); }
        if ($this->take('?')) { $this->atom($depth+1); $this->need(':'); $this->atom($depth+1); }
    }
    private function items(string $end,int $depth): void
    {
        while (!$this->take($end)) {
            $this->expression($depth);
            if ($this->take(T_DOUBLE_ARROW)) { $this->expression($depth); }
            if ($this->take($end)) { return; }
            $this->need(',');
        }
    }
    public function validate(): void
    {
        $this->need(T_RETURN); $this->expression(0); $this->need(';');
        if ($this->at !== count($this->tokens)) { refuse('CONFIG_SHAPE_REFUSED'); }
    }
}

function configShape(string $raw): void { (new LiteralConfig($raw))->validate(); }

function generatedConfig(string $raw,string $root): void
{
    $tokens=array_values(array_filter(token_get_all($raw),static function($t) {
        return !is_array($t) || !in_array($t[0],[T_OPEN_TAG,T_WHITESPACE,T_COMMENT,T_DOC_COMMENT],true);
    }));
    if (isset($tokens[0]) && is_array($tokens[0]) && $tokens[0][0]===T_RETURN) { configShape($raw); return; }
    // Composer's two generated assignments have no configurable executors.
    $expected='$vendorDir=dirname(__DIR__);$baseDir=dirname($vendorDir);';
    $joined=''; $at=0;
    while (strlen($joined)<strlen($expected) && $at<count($tokens)) { $token=$tokens[$at++];$joined.=is_array($token)?$token[1]:$token; }
    if ($joined!==$expected) { refuse('GENERATED_CONFIG_REFUSED'); }
    $literal='<?php ';
    foreach (array_slice($tokens,$at) as $token) {
        if (is_array($token) && $token[0]===T_VARIABLE) {
            if (!in_array($token[1],['$vendorDir','$baseDir'],true)) { refuse('GENERATED_CONFIG_REFUSED'); }
            $literal.=var_export($root.($token[1]==='$vendorDir'?'/vendor':''),true);
        } else { $literal.=is_array($token)?$token[1]:$token; }
        $literal.=' ';
    }
    configShape($literal);
}

function composerFiles(string $raw,string $root,int $publisher): void
{
    generatedConfig($raw,$root);
    $files=require $root.'/vendor/composer/autoload_files.php';
    if (!is_array($files) || count($files)>32) { refuse('VENDOR_PROFILE_REFUSED'); }
    foreach ($files as $file) {
        if (!is_string($file) || strpos($file,$root.'/vendor/')!==0) { refuse('VENDOR_PROFILE_REFUSED'); }
        checkedFile($file,$publisher);
    }
    // Installed Composer loader, eager files and lazy Yii/Dotenv classes are
    // the explicit dependency trust boundary, not newly attested source.
}

function declarationsOnly(string $raw): void
{
    $tokens=array_values(array_filter(token_get_all($raw),static function($t) {
        return !is_array($t) || !in_array($t[0],[T_OPEN_TAG,T_WHITESPACE,T_COMMENT,T_DOC_COMMENT],true);
    }));
    $at=0;
    while ($at<count($tokens)) {
        if (!is_array($tokens[$at]) || $tokens[$at][0]!==T_FUNCTION) { refuse('STARTUP_HOOK_REFUSED'); }
        while ($at<count($tokens) && $tokens[$at]!=='{') { ++$at; }
        if ($at===count($tokens)) { refuse('STARTUP_HOOK_REFUSED'); }
        $depth=0;
        do { $token=$tokens[$at++];if ($token==='{') {++$depth;} if ($token==='}') {--$depth;} } while ($at<count($tokens) && $depth>0);
        if ($depth!==0) { refuse('STARTUP_HOOK_REFUSED'); }
    }
}


function applicationShape(array $config, array $extensions): void
{
    foreach (array_keys($config) as $key) {
        if (!is_string($key) || strpos($key,'on ')===0 || strpos($key,'as ')===0
            || in_array($key,['container','class','extensions'],true)) { refuse('STARTUP_HOOK_REFUSED'); }
    }
    if (($config['bootstrap'] ?? null) !== ['log']) { refuse('STARTUP_HOOK_REFUSED'); }
    foreach ($extensions as $extension) {
        if (!is_array($extension) || isset($extension['bootstrap'])) { refuse('STARTUP_HOOK_REFUSED'); }
    }
    $components=$config['components'] ?? [];
    foreach (['errorHandler'=>'yii\\web\\ErrorHandler','request'=>'yii\\web\\Request',
              'response'=>'yii\\web\\Response','log'=>'yii\\log\\Dispatcher','db'=>'yii\\db\\Connection'] as $name=>$class) {
        if (!isset($components[$name])) { continue; }
        $definition=$components[$name];
        if (!is_array($definition) || (isset($definition['class']) && ltrim($definition['class'],'\\')!==$class)) { refuse('STARTUP_HOOK_REFUSED'); }
        foreach (array_keys($definition) as $key) {
            if (!is_string($key) || strpos($key,'on ')===0 || strpos($key,'as ')===0) { refuse('STARTUP_HOOK_REFUSED'); }
        }
    }
    foreach (array_keys($components['log'] ?? []) as $key) {
        if (!in_array($key,['class','traceLevel','targets'],true)) { refuse('STARTUP_HOOK_REFUSED'); }
    }
    if (isset($components['log']['traceLevel']) && (!is_int($components['log']['traceLevel']) || $components['log']['traceLevel']<0 || $components['log']['traceLevel']>5)) { refuse('STARTUP_HOOK_REFUSED'); }
    foreach (($components['log']['targets'] ?? []) as $definition) {
        if (!is_array($definition) || ltrim($definition['class'] ?? '', '\\')!=='yii\\log\\FileTarget') { refuse('STARTUP_HOOK_REFUSED'); }
        foreach (array_keys($definition) as $key) {
            if (!in_array($key,['class','levels','except','categories','logVars','enabled','prefix','logFile'],true)) { refuse('STARTUP_HOOK_REFUSED'); }
        }
        if (($definition['logVars'] ?? [])!==[] || (isset($definition['enabled']) && !is_bool($definition['enabled']))
            || (array_key_exists('prefix',$definition) && $definition['prefix']!==null)
            || (isset($definition['logFile']) && $definition['logFile']!==APP_ROOT.'/api/runtime/logs/app.log')) { refuse('STARTUP_HOOK_REFUSED'); }
        foreach (['levels','except','categories'] as $key) {
            if (!isset($definition[$key])) { continue; }
            if (!is_array($definition[$key])) { refuse('STARTUP_HOOK_REFUSED'); }
            foreach ($definition[$key] as $value) { if (!is_string($value)) { refuse('STARTUP_HOOK_REFUSED'); } }
        }
    }
}

function configuredApplication(int $publisher)
{
    if (class_exists('Yii', false) || defined('YII_DEBUG') || defined('YII_ENV')) { refuse('STARTUP_CONTEXT_REFUSED'); }
    $root=APP_ROOT;
    $raw=[];
    foreach (['common/config/main.php','common/config/main-local.php','api/config/main-local.php',
              'common/config/params.php','common/config/params-local.php','api/config/params.php','api/config/params-local.php'] as $relative) {
        $raw[$relative]=checkedFile($root.'/'.$relative,$publisher); configShape($raw[$relative]);
    }
    foreach (['api/web/index.php'=>'5f8fd4230de8f7cd2500cf226faa0a7952a762af73c75d8478aafe1c1082cb7e',
              'api/config/main.php'=>MAIN_DEFINITION_SHA,'common/config/bootstrap.php'=>COMMON_BOOTSTRAP_SHA,
              'api/config/bootstrap.php'=>EMPTY_BOOTSTRAP_SHA] as $relative=>$expected) {
        $raw[$relative]=checkedFile($root.'/'.$relative,$publisher);
        if (!hash_equals($expected,hash('sha256',$raw[$relative]))) { refuse('STARTUP_SOURCE_REFUSED'); }
    }
    // Installed vendor is not promoted to a new cryptographic source baseline.
    // Its generated autoload file list is constrained before it executes.
    $autoload=checkedFile($root.'/vendor/composer/autoload_files.php',$publisher);
    composerFiles($autoload,$root,$publisher);
    $extensions=checkedFile($root.'/vendor/yiisoft/extensions.php',$publisher);
    generatedConfig($extensions,$root);
    $extensionDefinitions=require $root.'/vendor/yiisoft/extensions.php';
    foreach ($extensionDefinitions as $definition) {
        if (!is_array($definition) || isset($definition['bootstrap'])) { refuse('STARTUP_HOOK_REFUSED'); }
    }
    declarationsOnly(checkedFile($root.'/common/helper/functions.php',$publisher));
    define('YII_DEBUG',false); define('YII_ENV','prod');
    require $root.'/vendor/autoload.php'; require $root.'/vendor/yiisoft/yii2/Yii.php';
    require $root.'/common/config/bootstrap.php'; require $root.'/api/config/bootstrap.php';
    $config=\yii\helpers\ArrayHelper::merge(require $root.'/common/config/main.php',require $root.'/common/config/main-local.php',
        require $root.'/api/config/main.php',require $root.'/api/config/main-local.php');
    applicationShape($config,$extensionDefinitions);
    if (($config['basePath'] ?? null)!==APP_ROOT.'/api' || ($config['vendorPath'] ?? null)!==APP_ROOT.'/vendor'
        || (isset($config['aliases']['@common']) && $config['aliases']['@common']!==APP_ROOT.'/common')) { refuse('MODEL_SOURCE_REFUSED'); }
    // Same complete definition and same standard constructor, never run().
    return new \yii\web\Application($config);
}

function loadModels(int $publisher): void
{
    if (\Yii::getAlias('@common')!==APP_ROOT.'/common') { refuse('MODEL_SOURCE_REFUSED'); }
    $pins=['Blogs'=>'3a7abf27993e296c812095974c0a5304506a24dff0aab22e4272f35b02766961',
           'Faq'=>'1466ddb683939ceb42cf75a7755cf511357543433588a6ab1317ea96fe969959',
           'FaqGroup'=>'261f583f7a57f889c46ca6b369dc9d4449bf394fed78e80911ee5f768d51ce28'];
    foreach ($pins as $name=>$expected) {
        $class='common\\models\\'.$name;$path=APP_ROOT.'/common/models/'.$name.'.php';
        if (class_exists($class,false)) { refuse('MODEL_SOURCE_REFUSED'); }
        foreach (spl_autoload_functions() ?: [] as $loader) {
            if (is_array($loader) && is_object($loader[0]) && get_class($loader[0])==='Composer\\Autoload\\ClassLoader') {
                $selected=$loader[0]->findFile($class);
                if ($selected!==false && realpath($selected)!==realpath($path)) { refuse('MODEL_SOURCE_REFUSED'); }
            }
        }
        if (!hash_equals($expected,hash('sha256',checkedFile($path,$publisher)))) { refuse('MODEL_SOURCE_REFUSED'); }
        // Explicit pinned include prevents a different lazy first-party class
        // body being executed before ReflectionMethod verifies inherited getDb.
        require $path;
        if ((new \ReflectionClass($class))->getFileName()!==$path) { refuse('MODEL_SOURCE_REFUSED'); }
    }
}
