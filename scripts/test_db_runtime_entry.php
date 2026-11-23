<?php
declare(strict_types=1);
// Fixed direct FastCGI SCRIPT_FILENAME outside every public document root.
// No product router/index/controller is patched by this preparation package.
error_reporting(0); ini_set('display_errors','0'); ini_set('log_errors','0');
$discarded=0;
ob_start(static function($chunk) use (&$discarded) { $discarded+=strlen($chunk); return ''; },1024);
try {
    require __DIR__.'/test_db_runtime_probe.php';
    require __DIR__.'/test_db_runtime_startup.php';
    require __DIR__.'/test_db_runtime_pdo.php';
    require __DIR__.'/test_db_runtime_php_channel.php';
    if (ini_get('auto_prepend_file')!=='' || ini_get('auto_append_file')!=='') { \JsmTestDbRuntime2760\refuse('STARTUP_CONTEXT_REFUSED'); }
    \JsmTestDbRuntime2760\privateEntry();
} catch (\Throwable $ignored) {
    // Private dialogue, never PHP error messages/stack/DSN on FastCGI output.
} finally {
    while (ob_get_level()>0) { ob_end_clean(); }
    http_response_code(204);
}
