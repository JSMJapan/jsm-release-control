<?php
declare(strict_types=1);
namespace JsmTestDbRuntime2760;

const METADATA_SQL = 'SELECT DATABASE() AS schema_name, CURRENT_USER() AS principal, VERSION() AS server_version, @@read_only AS server_read_only';

function connectionDefinition($app): array
{
    if (get_class($app) !== 'yii\\web\\Application') { refuse('APPLICATION_REFUSED'); }
    $db=$app->getDb();
    if (get_class($db)!=='yii\\db\\Connection' || $db->pdo!==null || $db->getBehaviors()!==[]
        || !in_array($db->masters,[null,[]],true) || !in_array($db->slaves,[null,[]],true) || $db->pdoClass!==null
        || $db->hasEventHandlers('afterOpen') || $db->hasEventHandlers('beforeOpen')) { refuse('DB_DEFINITION_REFUSED'); }
    foreach (['common\\models\\Blogs','common\\models\\Faq','common\\models\\FaqGroup'] as $model) {
        $method=new \ReflectionMethod($model,'getDb');
        if ($method->getDeclaringClass()->getName()!=='yii\\db\\ActiveRecord' || $model::getDb()!==$db) { refuse('DB_DEFINITION_REFUSED'); }
    }
    return nativeDefinition($db->dsn,$db->username,$db->password,$db->attributes ?? []);
}

function nativeDefinition($dsn,$username,$password,$attributes): array
{
    if (!is_string($dsn) || !is_string($username) || !is_string($password) || !is_array($attributes)
        || !preg_match('/\Amysql:([^\x00\r\n]+)\z/D',$dsn,$match)) { refuse('DB_DEFINITION_REFUSED'); }
    $fields=[];
    foreach (explode(';',$match[1]) as $pair) {
        if (!preg_match('/\A(host|port|dbname|charset)=([^;=]+)\z/D',$pair,$part) || isset($fields[$part[1]])) { refuse('DB_DEFINITION_REFUSED'); }
        $fields[$part[1]]=$part[2];
    }
    $port=$fields['port'] ?? '3306';
    if (($fields['host'] ?? null)!=='127.0.0.1' || !preg_match('/\A[1-9][0-9]{0,4}\z/D',$port) || (int)$port>65535
        || !preg_match('/\A[A-Za-z0-9_]{1,64}\z/D',$fields['dbname'] ?? '')
        || (isset($fields['charset']) && !in_array($fields['charset'],['utf8','utf8mb4'],true))) { refuse('DB_DEFINITION_REFUSED'); }
    $allowed=[\PDO::ATTR_ERRMODE,\PDO::ATTR_CASE,\PDO::ATTR_STRINGIFY_FETCHES,\PDO::ATTR_EMULATE_PREPARES,\PDO::ATTR_DEFAULT_FETCH_MODE,\PDO::ATTR_TIMEOUT,\PDO::ATTR_AUTOCOMMIT];
    foreach ($attributes as $key=>$value) {
        if (!is_int($key) || !in_array($key,$allowed,true) || (!is_int($value) && !is_bool($value))
            || ($key===\PDO::ATTR_AUTOCOMMIT && !in_array($value,[true,1],true))
            || ($key===\PDO::ATTR_TIMEOUT && (!is_int($value) || $value<1 || $value>1))) { refuse('PDO_ATTRIBUTE_REFUSED'); }
    }
    // Request-local diagnostic safety options; db definition is never mutated.
    $attributes[\PDO::ATTR_TIMEOUT]=1; $attributes[\PDO::ATTR_ERRMODE]=\PDO::ERRMODE_EXCEPTION;
    return ['dsn'=>$dsn,'username'=>$username,'password'=>$password,'attributes'=>$attributes,
            'target'=>['host'=>'127.0.0.1','port'=>(int)$port,'schema'=>$fields['dbname'],'same_db'=>true]];
}

function nativeConnect(array $definition)
{
    if (!extension_loaded('pdo_mysql') || !extension_loaded('mysqlnd')
        || ini_set('mysqlnd.net_read_timeout','1')===false || ini_get('mysqlnd.net_read_timeout')!=='1') { refuse('PDO_CAPABILITY_REFUSED'); }
    // No Connection::open, initConnection, charset SET, event, prepare or SQL.
    try { return new \PDO($definition['dsn'],$definition['username'],$definition['password'],$definition['attributes']); }
    catch (\PDOException $ignored) { refuse(($ignored->errorInfo[1] ?? null)===1045 ? 'PDO_AUTH_REFUSED' : 'PDO_CONNECT_REFUSED'); }
}

function metadata($pdo,string $schema): array
{
    try { $statement=$pdo->query(METADATA_SQL); } catch (\PDOException $ignored) { refuse('PDO_QUERY_REFUSED'); }
    $row=$statement->fetch(\PDO::FETCH_ASSOC); $extra=$statement->fetch(\PDO::FETCH_ASSOC); $statement->closeCursor();
    if (!is_array($row) || $extra!==false || !keys($row,['schema_name','principal','server_version','server_read_only'])
        || !is_string($row['schema_name']) || !is_string($row['principal']) || strlen($row['principal'])>256
        || !is_string($row['server_version']) || strlen($row['server_version'])>128
        || !in_array($row['server_read_only'],[0,1,'0','1'],true)) { refuse('METADATA_REFUSED'); }
    $version=$row['server_version'];
    $family=stripos($version,'MariaDB')!==false ? 'MARIADB' : (strpos($version,'5.7.')===0 ? 'MYSQL_5_7' : (strpos($version,'8.')===0 ? 'MYSQL_8' : 'OTHER'));
    return ['stage'=>'RESULT','schema_matches'=>hash_equals($schema,$row['schema_name']),
            'principal_kind'=>strpos($row['principal'],'root@')===0 ? 'ROOT' : 'OTHER',
            'version_family'=>$family,'server_read_only'=>((string)$row['server_read_only']==='1'),'query_count'=>1];
}

function phpDialogue($wire,callable $startup,callable $connect,callable $select): void
{
    $hello=$wire->receive('ROOT',0);
    try { $definition=$startup($hello['publisher_uid']); } catch (\Throwable $e) { phpFailure($wire,1,$e); throw $e; }
    $wire->send('PHP',1,array_merge(['stage'=>'TARGET'],$definition['target']));
    if ($wire->receive('ROOT',2)['stage']!=='OPEN') { refuse('ROOT_ABORTED'); }
    $pdo=null;
    try {
        try { $pdo=$connect($definition); } catch (\Throwable $e) { phpFailure($wire,3,$e); throw $e; }
        $wire->send('PHP',3,['stage'=>'CONNECTED','native_pdo'=>true]);
        if ($wire->receive('ROOT',4)['stage']!=='SELECT') { refuse('ROOT_ABORTED'); }
        try { $result=$select($pdo,$definition['target']['schema']); } catch (\Throwable $e) { phpFailure($wire,5,$e); throw $e; }
        $wire->send('PHP',5,$result);
        if ($wire->receive('ROOT',6)['accepted']!==true) { refuse('ROOT_ABORTED'); }
    } finally { $pdo=null; }
}

function phpFailure($wire,int $sequence,\Throwable $error): void
{
    $reason=get_class($error)==='RuntimeException' && in_array($error->getMessage(),PHP_REASONS,true) ? $error->getMessage() : 'INTERNAL_REFUSED';
    try { $wire->send('PHP',$sequence,['stage'=>'REFUSED','reason'=>$reason]); } catch (\Throwable $ignored) {}
}
