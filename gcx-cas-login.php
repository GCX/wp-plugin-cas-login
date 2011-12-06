<?php
/**
 * CAS Login (Authentication) Plugin
 * 
 * Login to WordPress through CAS (Central Authentication Service) using phpCAS.
 * @package GCX_CAS_Login
 * @subpackage Main
 * 
 * @uses phpCAS 1.2.0+
 */

/**
 * Plugin Name: CAS Login (Authentication)
 * Plugin URI:  https://github.com/GCX/php-wp-cas-login
 * Description: Login to WordPress through CAS (Central Authentication Service) using phpCAS.
 * Author:      Global ConneXion
 * Author URI:  https://github.com/GCX
 * Version:     0.1
 * Text Domain: caslogin
 * Domain Path: /languages/
 * License:     Modified BSD
 */
?>
<?php
/*
 * Copyright (c) 2011, CAMPUS CRUSADE FOR CHRIST
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 * 
 *     Redistributions of source code must retain the above copyright notice, this
 *      list of conditions and the following disclaimer.
 *     Redistributions in binary form must reproduce the above copyright notice,
 *      this list of conditions and the following disclaimer in the documentation
 *      and/or other materials provided with the distribution.
 *     Neither the name of CAMPUS CRUSADE FOR CHRIST nor the names of its
 *      contributors may be used to endorse or promote products derived from this
 *      software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */
?>
<?php
require_once 'Log.php';
global $logger;
$logger = Log::factory('file', ini_get('error_log'), substr(strtoupper(md5(microtime())), 0, 5));
?>
<?php

//if phpCAS in not loaded, attempt to include it
//from the include path, otherwise load the included phpCAS
if(!class_exists('CAS_Client')) {
	@include_once 'CAS.php';
	if(!class_exists('CAS_Client'))
		@include_once rtrim(dirname(realpath(__FILE__)), DIRECTORY_SEPARATOR) . '/lib/phpCAS/CAS.php';
}

/**
 * Implements CAS Authentication for wordpress logins
 * 
 * @author Brian Zoetewey <brian.zoetewey@ccci.org>
 */
class GCX_CAS_Login {
/*###########################################
 #   Singleton Methods
 ##########################################*/
	/**
	 * Singleton instance
	 * @var GCX_CAS_Login
	 */
	private static $instance;
	
	/**
	* Returns the GCX_CAS_Login singleton
	* @code $gcx_cas = GCX_CAS_Login::singleton();
	* @return GCX_CAS_Login
	*/
	public static function singleton() {
		if(!isset(self::$instance)) {
			$class = __CLASS__;
			self::$instance = new $class();
		}
		return self::$instance;
	}
	
	/**
	* Prevent cloning of the GCX_CAS_Login object
	*/
	private function __clone() {}
	
/*###########################################
#   Constants
##########################################*/
	/**
	 * Name of the library directory.
	 * @var string
	 */
	const LIB_DIR_NAME = 'lib';
	
	/**
	 * Name of the api directory.
	 * Change this if you rename the api directory.
	 * @var string
	 */
	const API_DIR_NAME = 'api';
	
	/**
	 * CAS proxy mode
	 * @var string
	 */
	const PROXY = 'proxy';
	
	/**
	 * CAS client mode
	 * @var string
	 */
	const CLIENT = 'client';
	
	/**
	 * CAS PGT file storage
	 * @var string
	 */
	const FILE = 'file';
	
	/**
	 * Configuration name
	 * 
	 * Name used for storing and retrieving config from the wordpress site options.
	 * @var string
	 */
	const CONFIG_NAME = 'gcx_cas_login_config';

	/**
	 * Base directory of this plugin
	 * Absolute path on the filesystem to this plugin.
	 * @var string
	 */
	public $base_dir;
	
	/**
	 * Base uri of this plugin
	 * 
	 * Absolute url for this plugin
	 * @var string
	 */
	public $base_uri_abs;
	
	/**
	 * Base relative uri
	 * 
	 * This is the relative path to this plugin. Use with
	 * site_url() or home_url() to create an absolute url.
	 * @var string
	 */
	public $base_uri_rel;
	
	/**
	 * Library directory path
	 * @var string
	 */
	public $lib_dir;

	/**
	 * Configuration defaults
	 * @var array
	 */
	private $config_defaults = array(
		'hostname'    => 'thekey.me',
		'port'        => '443',
		'uri'         => 'cas',
		'mode'        => self::CLIENT,
	);
	
	/**
	 * The CAS Client object
	 * @var CAS_Client
	 */
	private $_cas_client;
	
	/**
	 * GCX_CAS_Login class constructor
	 * 
	 * Do not instantiate this class, instead use the singleton object.
	 * @code $gcx_cas = GCX_CAS_Login::singleton();
	 */
	private function __construct() {
		$this->base_dir = rtrim(dirname(realpath(__FILE__)), DIRECTORY_SEPARATOR);
		$this->lib_dir = $this->base_dir . DIRECTORY_SEPARATOR . self::LIB_DIR_NAME;
		
		//Build the base relative uri by searching backwards until we encounter the wordpress ABSPATH
		$root = array_pop(explode(DIRECTORY_SEPARATOR, rtrim(ABSPATH, DIRECTORY_SEPARATOR)));
		$path_parts = explode(DIRECTORY_SEPARATOR, $this->base_dir);
		$parts = array();
		while($part = array_pop($path_parts)) {
			if($part == $root)
				break;
			array_unshift($parts, $part);
		}
		$this->base_uri_rel = '/' . implode('/', $parts);
		$this->base_uri_abs = get_site_url(null, $this->base_uri_rel);

		$this->register_actions();
	}
	
	/**
	 * Initializes phpCAS
	 * 
	 * @access private
	 */
	public function initialize_phpcas() {
		$config = $this->get_config();
		
//		phpCAS::setDebug(implode('/', array($this->base_dir, 'cas.log')));
		
		//Create a CAS Client object
		$this->_cas_client = new CAS_Client(
			'2.0',
			$config->mode == self::PROXY,
			$config->hostname,
			(int) $config->port,
			$config->uri
		);
		
		//Disable SSL server validation.
		//Validation usually fails unless reverse hostname lookup works correctly for the CAS server.
		$this->_cas_client->setNoCasServerValidation();

		//Accept logout requests from CAS, but do not validate the server.
		//(breaks because hostname reverse lookup does not resolve to our CAS server)
		$this->_cas_client->handleLogoutRequests(false);
	}
	
	
	/**
	 * Register WordPress actions and filters
	 */
	private function register_actions() {
		add_action('plugins_loaded', array(&$this, 'initialize_phpcas'), 0, 0);
		add_action('switch_blog', array(&$this, 'update_uris'), 0, 0);
		
		//Authentication hooks
		add_filter('authenticate', array(&$this, 'authenticate'), 10, 3);
		add_filter('login_url', array(&$this, 'remove_reauth_param'));
		add_action('check_passwords', array(&$this, 'check_passwords'), 10, 3);
		add_action('wp_logout', array(&$this, 'logout'));
		
		add_action('init', array(&$this, 'force_login'), 0, 0);
		
		add_filter('show_password_fields', '__return_false'); //Disable password change
		add_filter('allow_password_reset', '__return_false'); //Disable password change
	}
	
	
	/**
	 * Force Authentication
	 */
	public function force_login() {
		switch(basename($_SERVER['PHP_SELF'])) {
			case 'wp-login.php':
			case 'ajax-upload.php':
			case 'async-upload.php':
			case 'admin-ajax.php':
			case 'wp-cron.php':
			case 'wp-login.php':
			case 'upgrade.php':
			case 'cas-callback.php':
			case 'xmlrpc.php':
				return;
		}
		if(!is_user_logged_in()) {
			auth_redirect();
		}
	}
	
	/**
	 * Updates the uris when the blog is switched.
	 * 
	 * @see switch_blog
	 */
	public function update_uris() {
		$this->base_uri_abs = get_site_url(null, $this->base_uri_rel);
	}
	
	/**
	 * Get the CAS configuration
	 * @return object
	 */
	public function get_config() {
		return (object) wp_parse_args(get_site_option(self::CONFIG_NAME, array()), $this->config_defaults);
	}
	
	/**
	 * Returns the uri to use for CAS PGT callbacks
	 * @return string
	 */
	public function get_callback_uri() {
		return implode('/', array($this->base_uri_abs, self::API_DIR_NAME, self::CALLBACK_FILENAME));
	}
	
	
	/**
	 * Get the CAS_Client object
	 * @return CAS_Client
	 */
	public function get_cas_client() {
		return $this->_cas_client;
	}
	
	/**
	* Authenticates user through phpCAS, if user is not in the system, they get added.
	* callback for 'authenticate' wordpress action
	*/
	function authenticate() {
		global $wpdb;
		
		//Redirect to CAS if User is not already signed in.
		$this->_cas_client->forceAuthentication();
	
		//get users GUID from cas:attributes
		$casAttributes = (array) $this->_cas_client->getAttributes();
		if(is_array($casAttributes)) {
			if(array_key_exists('ssoGuid', $casAttributes)) {
				$guid = strtoupper((string)$casAttributes['ssoGuid']);
			}
			if(array_key_exists('firstName', $casAttributes)) {
				$first = (string)$casAttributes['firstName'];
			}
			if(array_key_exists('lastName', $casAttributes)) {
				$last = (string)$casAttributes['lastName'];
			}
		}

		//get users email address from cas login name
		$email = $this->_cas_client->getUser();
		
		//Find user by GUID first
		if($user = $this->get_user_by_guid($guid)) {
			$userdata = get_userdata($user->ID);
			if($userdata->user_login != $email || $userdata->user_email != $email) {
				if(!username_exists($email)) {
					$old_email = $userdata->user_email;
					$result = $wpdb->query(sprintf('UPDATE %1$s SET user_login="%2$s", user_email="%2$s" WHERE ID=%3$d', $wpdb->users, $wpdb->escape($email), $user->ID));
					wp_cache_delete($user->ID, 'users');
					wp_cache_delete($userdata->login_name, 'userlogins');
					$user = new WP_User($user->ID);
				}
			}
		}
		//We use email address as the wordpress username,
		elseif($userdata = get_user_by('login', $email)) {
			$user = new WP_User($userdata->ID);
			//check to see if the user has a guid set and it is the one provided from CAS
			if($g = get_user_meta($user->ID, 'guid', true)) {
				if($guid != $g) {
					//User GUIDs do not match, something is wrong.
					return new WP_Error('user_guid_mismatch', 'User GUID does not match CAS provided GUID.');
				}
			}
			else {
				update_user_meta($user->ID, 'guid', $guid);
			}
		}
		//Last chance, find user by email address
		elseif($userdata = get_user_by('email', $email)) {
			$user = new WP_User($userdata->ID);
			//check to see if the user has a guid set, if not set it
			if($g = get_user_meta($user->ID, 'guid', true)) {
				if($guid != $g) {
					//User GUIDs do not match, something is wrong.
					return new WP_Error('user_guid_mismatch', 'User GUID does not match CAS provided GUID.');
				}
			}
			else {
				//no guid set
				update_user_meta($user->ID, 'guid', $guid);
			}
			if(!username_exists($email)) {
				$old_email = $userdata->user_email;
				$result = $wpdb->query(sprintf('UPDATE %1$s SET user_login="%2$s", user_email="%2$s" WHERE ID=%3$d', $wpdb->users, $wpdb->escape($email), $user->ID));
				wp_cache_delete($user->ID, 'users');
				wp_cache_delete($userdata->user_login, 'userlogins');
				$user = new WP_User($user->ID);
			}
		}
		else {
			//User does not exist, add them.
			$userdata = array(
					'user_login' => $email,
					'user_email' => $email,
					'role' => 'subscriber',
					'nickname' => '',
			);
			if(isset($first) && isset($last)) {
				$userdata['first_name'] = $first;
				$userdata['last_name'] = $last;
				$display = $first . ' ' . $last;
				$userdata['user_nicename'] = $display;
				$userdata['display_name'] = $display;
			}
				
			//Switch to the primary blog when adding new users, this prevents the
			//user from being added to whatever blog might currently be running.
//			switch_to_blog((int)get_site_option('dashboard_blog', 1));
				
			//Add the new user
			$id = wp_insert_user($userdata);
				
			//Switch back to the running blog
//			restore_current_blog();
				
			if(is_wp_error($id)) return $id;
			$user = new WP_User($id);
				
			//add the GUID meta data
			update_user_meta($user->ID, 'guid', $guid);
				
			add_user_to_blog(get_current_blog_id(), $user->ID, 'subscriber');
		}
	
		if($user instanceof WP_User) {
			do_action('wpgcx_user_logged_in', $user->ID, $guid);
			return $user;
		}
		return false;
	}
	
	
	/**
	* Removes the reauth parameter from login urls, fixes an issue where
	* users are redirected back to wp-login after they have authenticated with CAS
	* if they initially request wp-admin, instead of clicking a login link.
	* callback for 'login_url' wordpress filter
	* @param string $login_url
	*/
	function remove_reauth_param($login_url) {
		$login_url = remove_query_arg('reauth', $login_url);
		return $login_url;
	}
	
	/**
	* Generates dummy password. Needed to create a user.
	* callback for 'check_passwords' wordpress action
	*/
	function check_passwords($username, $password1, $password2) {
		$password1 = $password2 = wp_generate_password();
	}
	
	/**
	* Wordpress logout hook, called after current user has logged out of wordpress.
	* This function will also log the user out of CAS if they are currently authenticated.
	* callback for 'wp_logout' wordpress action
	*/
	function logout() {
		if($this->_cas_client && $this->_cas_client->isAuthenticated()) {
			$this->_cas_client->logout(array());
		}
	}
	
	
	/**
	* Returns the current users GUID or GUEST if it is the guest user or they don't have a GUID set yet.
	* @return string guid or GUEST
	*/
	public function get_current_user_guid() {
		return $this->get_user_guid(wp_get_current_user());
	}
	
	/**
	 * Returns the guid for the specified user object
	 * @return guid string
	 */
	public function get_user_guid($user) {
		// User is not a guest user
		if($user instanceof WP_User && $user->ID !== 0) {
			// Check to see if the user has a valid guid
			$guid = get_user_meta($user->ID, 'guid', true);
			if(preg_match('/^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$/i', $guid)) {
				return $guid;
			}
		}
	
		// Default to the GUEST guid if a guid couldn't be found
		return 'GUEST';
	}
	
	/**
	 * Returns a WP_User object for the user matching the guid or null
	 * @param string $guid
	 * @return WP_User|null
	 */
	public function get_user_by_guid($guid) {
		if($userid = $this->get_user_id_by_meta('guid', $guid)) {
			return new WP_User($userid);
		}
		return null;
	}
	
	
	/**
	* Returns a user id for a user matching the meta information
	* @param string $meta_key
	* @param string $meta_value
	* @return user id or null
	*/
	public function get_user_id_by_meta($meta_key, $meta_value) {
		global $wpdb;
		$sql = "SELECT user_id FROM $wpdb->usermeta WHERE meta_key = '%s' AND meta_value = '%s'";
		return $wpdb->get_var($wpdb->prepare($sql, $meta_key, $meta_value));
	}
}

/**
* Override this method to prevent the wordpress auth cookies from being set
*/
function wp_set_auth_cookie($user_id, $remember = false, $secure = '') {
}

/**
 * Override the pluggable wp_validate_auth_cookie function to look up the user using the phpCAS session
 *
 * @return bool|int False if invalid session, User ID if valid.
 */
function wp_validate_auth_cookie($cookie = '', $scheme = '') {
	// determine which cookie is being used for the session
	if(empty($cookie)) {
		$cookie = is_ssl() ? SECURE_AUTH_COOKIE : AUTH_COOKIE;
	}

	// reopen the session to address the async-upload hack that changes session cookies and then re-runs this code
	if(!empty($_COOKIE[$cookie]) && $_COOKIE[$cookie] != session_id()) {
		session_commit();
		session_id($_COOKIE[$cookie]);
		session_start();
	}
	
	$cas_client = GCX_CAS_Login::singleton()->get_cas_client();

	// check to see if the user has authenticated with CAS yet
	if($cas_client && $cas_client->isAuthenticated() && $cas_client->hasAttribute('ssoGuid')) {
		// get the guid for the current user from CAS
		$guid = strtoupper($cas_client->getAttribute('ssoGuid'));

		// find the user id for the current guid
		$id = GCX_CAS_Login::singleton()->get_user_id_by_meta('guid', $guid);

		// return the user id or false if the user doesn't exist
		return is_null($id) ? false : $id;
	}

	// not a valid CAS session, so return false
	return false;
}


GCX_CAS_Login::singleton();