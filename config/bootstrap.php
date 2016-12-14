<?php

use lithium\aop\Filters;
use lithium\action\Dispatcher;
use lithium\storage\Session;

/**
 * Set the token header in the response.
 */
Filters::apply(Dispatcher::class, 'run', function($params, $next) {
	$response = $next($params);
	$configs = Session::config();

	foreach ($configs as $name => $config) {
		if ($config['adapter'] == 'Token') {
			$header = $config['header'];
			break;
		}
	}

	if (isset($header)) {
		$response->headers($header, Session::key($name));
	}

	return $response;
});