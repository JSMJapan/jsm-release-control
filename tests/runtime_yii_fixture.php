<?php
declare(strict_types=1);
namespace yii\base {
    class Component {public function __construct($config=[]) {}}
    class InvalidConfigException extends \RuntimeException {}
}
namespace {
    class CanaryLogger {public static $count=0;public $dispatcher;public function __construct(){++self::$count;}}
    class Yii {public static function createObject($definition){$class=$definition['class'];return new $class();}}
    require __DIR__.'/../scripts/test_db_runtime_probe.php';
    require __DIR__.'/../scripts/test_db_runtime_startup.php';
    require __DIR__.'/fixtures/runtime_yii_dispatcher.php';
    require __DIR__.'/fixtures/runtime_yii_request_methods.php';
    // Actual upstream constructor demonstrates why logger is an executor.
    new \yii\log\Dispatcher(['logger'=>['class'=>'CanaryLogger']]);
    if (CanaryLogger::$count!==1) {throw new \RuntimeException('OLD_CANARY_NOT_EXECUTED');}
    CanaryLogger::$count=0;$refused=false;
    try {
        \JsmTestDbRuntime2760\applicationShape(['bootstrap'=>['log'],'components'=>['log'=>['logger'=>['class'=>'CanaryLogger']]]],[]);
        new \yii\log\Dispatcher(['logger'=>['class'=>'CanaryLogger']]);
    } catch (\RuntimeException $e) {$refused=$e->getMessage()==='STARTUP_HOOK_REFUSED';}
    if (!$refused || CanaryLogger::$count!==0) {throw new \RuntimeException('CANARY_NOT_BLOCKED');}
    $params=json_decode($argv[1],true,16,JSON_THROW_ON_ERROR);
    $_SERVER=$params;
    if ((new \yii\web\Request())->getBaseUrl()!=='') {throw new \RuntimeException('CGI_BASE_URL_REFUSED');}
    unset($_SERVER['SCRIPT_NAME'],$_SERVER['PHP_SELF'],$_SERVER['DOCUMENT_ROOT']);$oldRefused=false;
    try {(new \yii\web\Request())->getBaseUrl();} catch (\yii\base\InvalidConfigException $e) {$oldRefused=true;}
    if (!$oldRefused) {throw new \RuntimeException('OLD_CGI_NOT_REFUSED');}
    echo "YII_NATIVE_FIXTURES_PASS\n";
}
