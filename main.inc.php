<?php
/*
Plugin Name: OpenId Connect
Version: 2.0.4
Description: This plugin provides OpenID Connect integration.
Plugin URI: https://piwigo.org/ext/index.php?eid=1049
Author: ProximApp (originally Jasper Weyne)
Author URI: https://github.com/ProximApp/PiwigoOpenIdConnectNext
Has Settings: true
*/

/*
   Copyright 2020-2021 Jasper Weyne

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

defined('PHPWG_ROOT_PATH') or die('Hacking attempt!');

/// Define plugin constants
global $prefixeTable;
define('OIDC_ID',      basename(dirname(__FILE__)));
define('OIDC_PATH' ,   PHPWG_PLUGINS_PATH . OIDC_ID . '/');
define('OIDC_ADMIN',   get_root_url() . 'admin.php?page=plugin-' . OIDC_ID);
define('OIDC_SESSION', OIDC_ID);
define('OIDC_TABLE',   $prefixeTable . "oidc");

require(OIDC_PATH . 'oidc.php');

/// Link event handlers
// The menubar is cached in the block manager before applying the full template
add_event_handler('plugins_loaded', 'oidc_init'); // earliest init possible
add_event_handler('load_profile_in_template', 'oidc_profile');
add_event_handler('blockmanager_apply', 'override_login_link');
add_event_handler('loc_begin_password', 'oidc_redirect');
add_event_handler('loc_begin_register', 'oidc_redirect');
add_event_handler('try_log_user', 'password_login');
add_event_handler('loc_end_identification', 'oidc_identification');
add_event_handler('user_init', 'refresh_login');
add_event_handler('get_admin_plugin_menu_links', 'oidc_admin_link');
add_event_handler('delete_user', 'oidc_delete_user');
add_event_handler('ws_add_methods', 'oidc_api');

/// Utility methods
/**
 * Generate a random password
 * based on: https://stackoverflow.com/questions/4356289/php-random-string-generator/31107425#31107425
 */
function random_pass($length = 16, $keyspace = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_-=+;:,.?")
{
	$pieces = [];
    $max = mb_strlen($keyspace, '8bit') - 1;
    for ($i = 0; $i < $length; ++$i) {
        $pieces []= $keyspace[random_int(0, $max)];
    }
    return implode('', $pieces);
}

/**
 * Check whether an access token or OpenID token isn't expired.
 */
function is_token_unexpired($access_token, $oidc): bool
{
	if (isset($access_token->expires)) {
		return $access_token->expires >= time();
	} else {
		// If user info retrieval is successful, token is still valid
		try {
			$oidc->setAccessToken($access_token->access_token);
			$oidc->requestUserInfo();
			return true;
		} catch (\Exception $e) {
			return false;
		}
	}
}

/// Event handlers
/**
 * Deserialize the database-stored contents of plugin settings
 * Override them with contents of conf.php
 */
function oidc_init()
{
	global $conf;
	$conf['OIDC'] = safe_unserialize($conf['OIDC']);

	if (file_exists(OIDC_PATH . 'conf.php')) {
		$overrideConfig = (include OIDC_PATH . 'conf.php');
		$conf['OIDC'] = array_merge($conf['OIDC'], $overrideConfig);
	}

	// When OpenID Connect is enforced, disable the core password login
	// (identification.php, pwg.session.login, pwg.images.uploadAsync).
	// The webmaster fallback calls pwg_login() itself, see password_login().
	if (oidc_enforced()) {
		remove_event_handler('try_log_user', 'pwg_login');
	}
}

/**
 * Removes the Profile/Registration block.
 */
function oidc_profile()
{
	global $template;

	if (isset($_SESSION[OIDC_SESSION])) {
		$template->assign('SPECIAL_USER', true);
	}
}

/**
 * Rewrite the login link in menu to link to the authorization code flow
 */
function override_login_link()
{
	global $template;

	// If U_LOGIN is present and authorization grant is enabled, replace U_LOGIN link
	if ($template->get_template_vars('U_LOGIN') !== null && can_authorization_grant())
		$template->assign('U_LOGIN', OIDC_PATH . 'auth.php');

	// If resource owner credentials grant is enabled, set U_REGISTER to registration url
	if (can_resource_owner_credentials_grant()) {
		if (!empty($conf['OIDC']['registration_url']))
			$template->assign('U_REGISTER', $conf['OIDC']['registration_url']);
		else
			$template->clear_assign('U_REGISTER');
	}
}

/**
 * Rewrite the contents of the identification.php where applicable 
 */
function oidc_identification()
{
	global $template;
	global $conf;

	// The local login form stays reachable for the webmaster fallback,
	// with identification.php?oidc_local=1
	$local_form = oidc_local_webmaster_login_enabled()
		&& (isset($_GET['oidc_local']) || isset($_POST['login']));
	if (!$local_form) {
		redirect_auth();
	}

	if (can_resource_owner_credentials_grant()) {
		if ($template->get_template_vars('U_LOST_PASSWORD') !== null) {
			// Password lost URL
			if (!empty($conf['OIDC']['password_reset_url']))
				$template->assign('U_LOST_PASSWORD', $conf['OIDC']['password_reset_url']);
			else
				$template->clear_assign('U_LOST_PASSWORD');
		}

		if ($template->get_template_vars('U_REGISTER') !== null) {
			// Registration URL
			if (!empty($conf['OIDC']['registration_url']))
				$template->assign('U_REGISTER', $conf['OIDC']['registration_url']);
			else
				$template->clear_assign('U_REGISTER');
		}
	}
}

/**
 * Redirect for password.php and register.php if applicable 
 */
function oidc_redirect()
{
	redirect_auth();

	if (can_resource_owner_credentials_grant()) {
		redirect(get_root_url() . 'identification.php');
	}
}

/**
 * Check the session of the logged in user on every request, refresh the
 * OpenID Connect token if needed, log out if expired.
 *
 * Fails closed: when OpenID Connect is enforced, a logged in session without
 * OpenID Connect token is logged out, except for the explicitly allowed
 * authentication contexts.
 */
function refresh_login($user)
{
	global $conf;

	if (!oidc_enforced()) {
		return;
	}

	// Guest: nothing to check
	if ($user['id'] == $conf['guest_id']) {
		return;
	}

	// Allowed authentication contexts without OpenID Connect token:
	// - API key in the X-PIWIGO-API header (stateless, no session),
	// - API key used with pwg.session.login,
	// - authentication keys (?auth= links sent by e-mail, created by admins)
	if (defined('PWG_API_KEY_REQUEST')) {
		return;
	}
	$connected_with = $_SESSION['connected_with'] ?? null;
	if (in_array($connected_with, ['api_key', 'auth_key', 'ws_session_login_api_key'], true)) {
		return;
	}

	if (empty($_SESSION[OIDC_SESSION])) {
		// Webmaster local login fallback
		if (oidc_local_session_allowed($user)) {
			return;
		}
		oidc_logout();
	}

	// The token must belong to the logged in user
	$accessToken = json_decode($_SESSION[OIDC_SESSION]);
	if (!is_object($accessToken) || !isset($accessToken->uid) || (int)$accessToken->uid !== (int)$user['id']) {
		oidc_logout();
	}

	// If the token is not expired, refreshing isn't necessary
	$oidc = get_oidc_client();
	if (is_token_unexpired($accessToken, $oidc)) {
		return;
	}

	if (empty($accessToken->refresh_token)) {
		oidc_logout();
	}

	// Try to obtain refreshed access token
	try {
		$response = $oidc->refreshToken($accessToken->refresh_token);
		if (!isset($response->access_token)) {
			oidc_logout();
		}
		$accessToken->access_token = $response->access_token;
		if (isset($response->refresh_token)) {
			$accessToken->refresh_token = $response->refresh_token;
		}
		if (isset($response->expires_in)) {
			$accessToken->expires = time() + $response->expires_in;
		} else {
			unset($accessToken->expires);
		}
		$_SESSION[OIDC_SESSION] = json_encode($accessToken);
	} catch (\Exception $e) {
		// Log out if an unknown problem arises
		oidc_logout();
	}
}

/**
 * try_log_user handler: resource owner credentials flow, and local login
 * fallback for webmasters.
 *
 * When OpenID Connect is enforced, the core pwg_login handler is removed
 * (see oidc_init()), so local passwords are not checked at all, except for
 * the webmaster fallback.
 */
function password_login($success, $username, $password, $remember_me)
{
	// If user is logged in through another hook, skip
	if ($success === true) {
		return true;
	}

	// Not enforced: the core pwg_login handler already did the job
	if (!oidc_enforced()) {
		return false;
	}

	// Webmaster local login fallback, only through the Piwigo login page
	// ($username and $password are still escaped by Piwigo, as pwg_login expects)
	if (oidc_local_webmaster_login_enabled() && script_basename() == 'identification') {
		$found = find_user_by_username_or_email($username);
		if (($found['status'] ?? null) === 'webmaster' && pwg_login(false, $username, $password, $remember_me)) {
			return true;
		}
	}

	if (!can_resource_owner_credentials_grant()) {
		trigger_notify('login_failure', stripslashes($username));
		return false;
	}

	// Try to request token with auth params
	// Piwigo addslashes() the request parameters, the provider needs the raw values
	$success = false;
	$oidc = get_oidc_client();
	$oidc->addAuthParam([
		'username' => stripslashes($username),
		'password' => stripslashes($password),
	]);

	try {
		$response = $oidc->requestResourceOwnerToken(true);
		if (isset($response->access_token)) {
			$oidc->setAccessToken($response->access_token);
			$success = oidc_login($oidc, $response, false);
		}
	} catch (\Exception $e) {
		// silently fail
	}

	// If login unsuccessful, trigger login_failure accordingly
	if (!$success) {
		trigger_notify('login_failure', stripslashes($username));
	}

	return $success;
}

/**
 * Add OpenID Connect menu entry to plugins
 */
function oidc_admin_link($menu) 
{
	$menu[] = [
    	'NAME' => 'OpenID Connect',
    	'URL' => OIDC_ADMIN,
	];
	return $menu;
}

/**
 * Delete users from the OIDC user table if applicable
 */
function oidc_delete_user($user_id)
{
	$query = '
	DELETE FROM '.OIDC_TABLE.'
	  WHERE `user_id` = \''.(int)$user_id.'\'
	;';
	pwg_query($query);
}

/**
 * Register WS API methods 
 */
function oidc_api($params)
{
	$service = &$params[0];
	$service->addMethod(
		'pwg.session.login_oidc',
		'api_login',
		array(
			'access_token' => array(),
		),
		'Tries to login the user using an OIDC token.',
		OIDC_PATH . 'api.php',
		array('post_only' => true)
	);
}
?>