<?php
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

require __DIR__ . '/vendor/autoload.php';

use Jumbojett\OpenIDConnectClient;

/**
 * Create an instance of OpenIDConnectClient with the configured settings
 */
function get_oidc_client() {
	global $conf;
	$config = $conf['OIDC'];
	
	// Create OIDC client
	$oidc = new OpenIDConnectClient(
		$config['issuer_url'] ?? '',
		$config['client_id'] ?? '',
		$config['client_secret'] ?? ''
	);

	// Set verification bits
	$oidc->setVerifyHost(!empty($config['verify_host']));
	$oidc->setVerifyPeer(!empty($config['verify_peer']));

	// The library builds the redirect URL from SERVER_PORT by default, which
	// is wrong behind a reverse proxy or a port mapping
	$oidc->setRedirectURL(oidc_redirect_url());

	// Set HTTP proxy
	if (!empty($config['proxy'])) {
		$oidc->setHttpProxy($config['proxy']);
	}

	// Set auth params
	$authparam = json_decode($config['authparam'] ?? '', true);
	if (is_array($authparam)) {
		$oidc->addAuthParam($authparam);
	}

	// Set scopes
	$oidc->addScope(array_values(array_filter(explode(' ', $config['scope'] ?? ''))));

	return $oidc;
}

/**
 * URL of auth.php, the redirect URL to register with the provider.
 * Can be overridden with 'redirect_url' in conf.php (e.g. behind a reverse proxy).
 */
function oidc_redirect_url() {
	global $conf;
	if (!empty($conf['OIDC']['redirect_url'])) {
		return $conf['OIDC']['redirect_url'];
	}
	return get_absolute_root_url() . 'plugins/' . OIDC_ID . '/auth.php';
}

/**
 * Relative URL of auth.php, from the current page
 */
function oidc_auth_url() {
	return get_root_url() . 'plugins/' . OIDC_ID . '/auth.php';
}

/**
 * Return whether the authorization code flow is enabled from config
 */
function can_authorization_grant() {
	global $conf;
	return !empty($conf['OIDC']['authorization_code_flow']);
}

/**
 * Return whether the resource owner credentials flow is enabled from config
 */
function can_resource_owner_credentials_grant() {
	global $conf;
	return !empty($conf['OIDC']['password_flow']);
}

/**
 * Return whether OpenID Connect is enforced, i.e. local password logins are disabled
 */
function oidc_enforced() {
	return can_authorization_grant() || can_resource_owner_credentials_grant();
}

/**
 * Return whether the local (password) login fallback for webmasters is enabled
 */
function oidc_local_webmaster_login_enabled() {
	global $conf;
	return !empty($conf['OIDC']['local_webmaster_login']);
}

/**
 * Return whether a session without OpenID Connect token is allowed for $user,
 * while OpenID Connect is enforced: only webmasters logged in through the
 * Piwigo login page (or its remember-me cookie), if the fallback is enabled.
 */
function oidc_local_session_allowed($user) {
	return oidc_local_webmaster_login_enabled()
		&& ($user['status'] ?? null) === 'webmaster'
		&& ($_SESSION['connected_with'] ?? null) === 'pwg_ui';
}

/**
 * Redirect a user to the auth.php page if enabled
 * If disabled, returns false
 */ 
function redirect_auth()
{
	if (can_authorization_grant()) {
		redirect(oidc_auth_url());
		return true;
	}

	return false;
}

/**
 * Get the preferred username of the resource owner
 * Resource owner is authenticated by the access token, stored in $oidc
 */
function get_preferred_username(OpenIDConnectClient $oidc) {
	global $conf;
	$config = $conf['OIDC'];

	// Note: this value must be unique, therefore we use sub
	$name = $oidc->requestUserInfo('sub');
	if (!empty($config['preferred_username'])) {
		$preferred = $oidc->requestUserInfo($config['preferred_username']);
		if (is_string($preferred) && $preferred !== '') {
			$name = $preferred;
		}
	}

	return $name;
}

/// Login/logout methods
/**
 * Report a failed registration: to the user, who is authenticated at the
 * provider but cannot be logged in, and to the administrator in the PHP log.
 *
 * @param string $name username from the provider
 * @param string[] $errors messages of register_user()
 */
function oidc_registration_failed($name, array $errors)
{
	if (empty($errors)) {
		$errors[] = l10n('Registration failed');
	}
	// Displayed like the errors of Piwigo's register.php (page_errors are not
	// escaped by the templates)
	$_SESSION['page_errors'] = array_merge($_SESSION['page_errors'] ?? [], $errors);
	// error_log() and not trigger_error(): never displayed in the page, even
	// with display_errors on. The username comes from the provider: control
	// characters are escaped so that it cannot forge log lines.
	error_log('OpenIdConnect: registration of user "' . addcslashes((string)$name, "\0..\37\\\"") . '" failed: ' . implode(' / ', $errors));
}

/**
 * Retrieve Piwigo user associated with the current OIDC resource owner
 * Resource owner is authenticated by the access token, stored in $oidc
 */
function oidc_retrieve(OpenIDConnectClient $oidc, $force_registration = false) {
	global $conf;
	$config = $conf['OIDC'];

	// Fetch user data
	$sub = $oidc->requestUserInfo('sub');
	$email = $oidc->requestUserInfo('email');
	$name = get_preferred_username($oidc);

	// Try to find the resource owner in the OIDC user table
	$query = '
		SELECT `user_id` AS id
		FROM ' . OIDC_TABLE . '
		WHERE `sub` = \'' . pwg_db_real_escape_string($sub) . '\';';
	$row = pwg_db_fetch_assoc(pwg_query($query));

	// If the user is not found, try to register
	if (empty($row['id'])) {
		if ($config['register_new_users'] || $force_registration) {
			// Registration is allowed, overwrite $row
			// register_user() expects SQL-escaped input (like Piwigo's addslashes'd $_POST),
			// while the claims returned by the provider are raw values.
			// But it also validates these escaped values, which has two side effects
			// for values containing quotes or backslashes, handled here:
			//  - the username collision check escapes the login a second time,
			//    so the check is done here on the raw value;
			//  - the e-mail format check fails (e.g. o\'brien@example.com), so the
			//    user is registered without e-mail, oidc_login() sets it right after.
			if (get_userid($name) !== false) {
				// Username already used by another account
				oidc_registration_failed($name, [l10n('this login is already used')]);
				return null;
			}
			$escaped_email = pwg_db_real_escape_string((string)$email);
			if ($escaped_email !== (string)$email) {
				$escaped_email = '';
			}
			$errors = [];
			$user_id = register_user(
				pwg_db_real_escape_string($name),
				random_pass(),
				$escaped_email,
				$config['notify_admins_on_register'],
				$errors,
				$config['notify_user_on_register']
			);
			if ($user_id === false || !empty($errors)) {
				// Registration failed (e.g. e-mail already used), do not link the sub
				oidc_registration_failed($name, $errors);
				return null;
			}
			$row['id'] = (int)$user_id;
			// single_insert() does not escape values
			single_insert(OIDC_TABLE, [
				'sub' => pwg_db_real_escape_string($sub),
				'user_id' => $row['id'],
			]);
		} else {
			// Registration is not allowed, fail
			return null;
		}
	}

	$row['id'] = (int)$row['id'];

	// Groups registration //

	// If the group management setting is enabled, synchronize the groups of
	// the user with the groups claim. The groups are left untouched if the
	// provider does not return the claim.
	if (!empty($config['manage_groups'])) {
		// 'group_claim' is the legacy name of the setting
		$groups_claim = $config['groups_claim'] ?? $config['group_claim'] ?? '';
		if ($groups_claim === '') {
			$groups_claim = 'groups';
		}

		$groups = $oidc->requestUserInfo($groups_claim);
		if (is_array($groups)) {
			oidc_sync_groups($row['id'], $groups);
		}
	}

	return $row['id'];
}

/**
 * Make $group_names the groups of the user $user_id, creating missing groups
 */
function oidc_sync_groups($user_id, array $group_names)
{
	$group_ids = [];
	foreach ($group_names as $group_name) {
		if (!is_string($group_name) || trim($group_name) === '') {
			continue;
		}
		$escaped_name = pwg_db_real_escape_string(trim($group_name));

		$query = '
SELECT id FROM `' . GROUPS_TABLE . '`
  WHERE name = \'' . $escaped_name . '\'
;';
		$group_row = pwg_db_fetch_assoc(pwg_query($query));

		if (empty($group_row['id'])) {
			// Create the group, like pwg.groups.add
			single_insert(GROUPS_TABLE, [
				'name' => $escaped_name,
				'is_default' => boolean_to_string(false),
			]);
			$group_ids[] = (int)pwg_db_insert_id();
		} else {
			$group_ids[] = (int)$group_row['id'];
		}
	}
	$group_ids = array_values(array_unique($group_ids));
	sort($group_ids);

	$query = '
SELECT group_id FROM ' . USER_GROUP_TABLE . '
  WHERE user_id = ' . (int)$user_id . '
  ORDER BY group_id
;';
	$current_ids = array_map('intval', query2array($query, null, 'group_id'));

	if ($current_ids === $group_ids) {
		return;
	}

	pwg_query('DELETE FROM ' . USER_GROUP_TABLE . ' WHERE user_id = ' . (int)$user_id . ';');
	foreach ($group_ids as $group_id) {
		single_insert(USER_GROUP_TABLE, [
			'user_id' => (int)$user_id,
			'group_id' => $group_id,
		]);
	}

	// Permissions depend on groups: rebuild the permissions cache of the user
	pwg_query('UPDATE ' . USER_CACHE_TABLE . ' SET need_update = \'true\' WHERE user_id = ' . (int)$user_id . ';');
}

/**
 * Log the Piwigo user associated with the provided $token, through the current $oidc session
 */
function oidc_login(OpenIDConnectClient $oidc, $token, $remember_me)
{
	global $conf;

	// Find user in piwigo database
	$id = oidc_retrieve($oidc);
	if ($id === null) {
		return false;
	}

	$name = get_preferred_username($oidc);
	$email = $oidc->requestUserInfo('email');

	// Update user data from ID token data
	$fields = array($conf['user_fields']['email'], $conf['user_fields']['username']);

	// mass_updates() does not escape values, claims returned by the provider must be escaped
	$data = array();
	$data[$conf['user_fields']['id']] = (int)$id;
	$data[$conf['user_fields']['email']] = pwg_db_real_escape_string($email);
	$data[$conf['user_fields']['username']] = pwg_db_real_escape_string($name);
	
	mass_updates(USERS_TABLE,
				array(
				'primary' => array($conf['user_fields']['id']),
				'update' => $fields
				),
				array($data));

	// Same checks as the core pwg_login(): no guest account
	$user_found = oidc_get_user_row($id);
	if (empty($user_found) || $id == $conf['guest_id'] || $user_found['status'] === 'guest') {
		trigger_notify('login_failure', $name);
		return false;
	}

	// Let other plugins check the login (2FA, account lockout...), like pwg_login()
	$state = [
		'can_login' => true,
		'reason' => null,
		'authenticated' => false,
	];
	if ($conf['OIDC']['apply_login_checks'] ?? true) {
		$state = trigger_change('finalize_login', $state, $user_found, false);
	}
	if (empty($state['can_login'])) {
		pwg_activity('user', $id, $state['reason'] ?? 'login_failure_before_log_user');
		trigger_notify('login_failure_before_log_user', $name);
		return false;
	}

	// Log the user in, unless a plugin handles log_user() itself
	// Remember-me is disabled: auto_login() would restore a session without
	// OpenID Connect token, which refresh_login() rejects
	if (empty($state['authenticated'])) {
		log_user($id, false);
	}

	// Store the tokens in the session, once the login is accepted
	// (log_user() regenerates the session id but keeps its content)
	oidc_store_token($token, $id);

	trigger_notify('login_success', $name);

	return true;
}

/**
 * Return the user row passed to the finalize_login handlers, in the same
 * format as find_user_by_username_or_email()
 */
function oidc_get_user_row($user_id)
{
	global $conf;

	$query = '
SELECT
  u.' . $conf['user_fields']['id'] . ' AS id,
  u.' . $conf['user_fields']['username'] . ' AS username,
  u.' . $conf['user_fields']['email'] . ' AS email,
  u.' . $conf['user_fields']['password'] . ' AS password,
  i.status
FROM ' . USERS_TABLE . ' AS u
  LEFT JOIN ' . USER_INFOS_TABLE . ' AS i ON u.' . $conf['user_fields']['id'] . ' = i.user_id
WHERE u.' . $conf['user_fields']['id'] . ' = ' . (int)$user_id . '
;';
	$row = pwg_db_fetch_assoc(pwg_query($query));
	if (empty($row)) {
		return null;
	}
	$row['status'] = $row['status'] ?? 'normal';
	return $row;
}

/**
 * Store the OpenID Connect tokens of the user $user_id in the session
 */
function oidc_store_token($token, $user_id)
{
	$encoded = ['uid' => (int)$user_id];
	if (isset($token->access_token)) {
		$encoded['access_token'] = $token->access_token;
	}
	if (isset($token->refresh_token)) {
		$encoded['refresh_token'] = $token->refresh_token;
	}
	if (isset($token->expires_in)) {
		$encoded['expires'] = time() + $token->expires_in;
	}
	$_SESSION[OIDC_SESSION] = json_encode($encoded);
}

/**
 * Log out the currently logged in user and redirect to the login page
 */
function oidc_logout()
{
	if (isset($_SESSION['pwg_uid'])) {
		logout_user();
	} else {
		unset($_SESSION[OIDC_SESSION]);
	}

	// Webservice: answer with an error instead of an HTML redirection
	if (script_basename() == 'ws') {
		include_once(PHPWG_ROOT_PATH . 'include/ws_init.inc.php');
		$service->sendResponse(new PwgError(401, 'Session expired, please log in again'));
		exit();
	}

	redirect_auth() or redirect(get_root_url() . 'identification.php');
}
?>