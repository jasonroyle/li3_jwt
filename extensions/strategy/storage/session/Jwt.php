<?php

namespace li3_jwt\extensions\strategy\storage\session;

use lithium\core\ConfigException;

/**
 * This strategy allows you to encode and decode your `Token` data using `JSON Web Tokens`.
 * You must provide a secret key, otherwise an exception is raised.
 */
class Jwt extends \lithium\core\Object {

	/**
	 * Dynamic class dependencies.
	 *
	 * @var array
	 */
	protected $_classes = ['jwt' => '\Firebase\JWT\JWT'];

	/**
	 * Default configuration.
	 *
	 * @var array
	 */
	protected $_defaults = ['algorithm' => 'HS256'];

	/**
	 * Constructor.
	 *
	 * @param array $config Configuration array. You can override the default algorithm.
	 */
	public function __construct(array $config = []) {
		if (!isset($config['secret'])) {
			throw new ConfigException('Jwt strategy requires a secret key.');
		}
		parent::__construct($config + $this->_defaults);
	}

	/**
	 * Read method.
	 *
	 * @param array $data the Data being read.
	 * @param array $options Options for this method.
	 * @return mixed Returns the decoded key or the dataset.
	 */
	public function read($data, array $options = []) {
		$class = $options['class'];

		$token = $class::read(null, ['strategies' => false]);
		$payload = $token ? (array) $this->_decode($token) : [];
		$key = isset($options['key']) ? $options['key'] : null;

		if ($key) return isset($payload[$key]) ? $payload[$key] : null;
		return $payload;
	}

	/**
	 * Write method.
	 *
	 * @param mixed $data The data to be encoded.
	 * @param array $options Options for this method.
	 * @return string Returns the json web token.
	 */
	public function write($data, array $options = []) {
		$class = $options['class'];

		$payload = $this->read(null, ['key' => null] + $options) ?: [];
		$payload = [$options['key'] => $data] + $payload;
		$class::key($options['name'], $this->_encode($payload));

		return $payload;
	}

	/**
	 * Encode a data array.
	 *
	 * @param array $data The data to be encoded.
	 * @return string Returns the json web token.
	 */
	protected function _encode($data = []) {
		$jwt = $this->_classes['jwt'];

		return $jwt::encode($data, $this->_config['secret'], $this->_config['algorithm']);
	}

	/**
	 * Decode a json web token.
	 *
	 * @param string $token The json web token to decode.
	 * @return array Returns the json web token payload.
	 */
	protected function _decode($token) {
		$jwt = $this->_classes['jwt'];

		return $jwt::decode($token, $this->_config['secret'], [$this->_config['algorithm']]);
	}

}
