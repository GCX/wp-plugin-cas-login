<?php
	define('WPGCX_DISABLE_HOOKS', true);
	define('WPGCX_DISABLE_FEATURES', true);
	define('WPGCX_CAS_CALLBACK', true);
	define('WP_USE_THEMES', false);
	require_once(realpath($_SERVER['DOCUMENT_ROOT'] . '/wp-load.php'));
	GCX_CAS_Login::singleton()->get_cas_client()->forceAuthentication();
?>
<html>
	<head>
		<title>CAS Callback Handler</title>
	</head>
	<body>
	</body>
</html>
