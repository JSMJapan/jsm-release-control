<?php
declare(strict_types=1);
namespace yii\db {class ActiveRecord {}}
namespace Composer\Autoload {
    class ClassLoader {
        public function loadClass($class) {}
        public function findFile($class) {return '/private/other.php';}
    }
}
namespace {
    class Yii {public static $alias;public static function getAlias($name){return self::$alias;}}
    require __DIR__.'/../scripts/test_db_runtime_probe.php';
    require __DIR__.'/../scripts/test_db_runtime_startup.php';
    $mode=$argv[1];$root=__DIR__.'/tmp-model-'.bin2hex(random_bytes(8));$GLOBALS['model_canary']=0;
    mkdir($root,0700);mkdir($root.'/common',0700);mkdir($root.'/common/models',0700);
    $pins=[];
    try {
        foreach (['Blogs','Faq','FaqGroup'] as $name) {
            $raw='<?php namespace common\\models; class '.$name.' extends \\yii\\db\\ActiveRecord {}';
            $pins[$name]=hash('sha256',$raw);
            if ($mode==='canary' && $name==='Blogs') {$raw='<?php namespace common\\models; $GLOBALS["model_canary"]++; class Blogs {}';}
            file_put_contents($root.'/common/models/'.$name.'.php',$raw);
        }
        Yii::$alias=$mode==='alias' ? '/private/other' : $root.'/common';
        if ($mode==='resolver') {spl_autoload_register([new \Composer\Autoload\ClassLoader(),'loadClass']);}
        $refused=false;
        try {\JsmTestDbRuntime2760\guardedModels(getmyuid(),$root,$pins);}
        catch (\Throwable $error) {$refused=get_class($error)==='RuntimeException' && $error->getMessage()==='MODEL_SOURCE_REFUSED';}
        if ($GLOBALS['model_canary']!==0 || ($mode==='valid' ? $refused || !class_exists('common\\models\\Blogs',false) : !$refused)) {
            throw new \RuntimeException('MODEL_FIXTURE_FAILED');
        }
        echo "MODELS_NATIVE_FIXTURES_PASS\n";
    } finally {
        foreach (['Blogs','Faq','FaqGroup'] as $name) {unlink($root.'/common/models/'.$name.'.php');}
        rmdir($root.'/common/models');rmdir($root.'/common');rmdir($root);
    }
}
