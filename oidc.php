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
 * Normalize the issuer URL entered by the administrator.
 *
 * The library adds /.well-known/openid-configuration itself, but the
 * discovery URL is often entered instead of the issuer: remove it, and the
 * trailing slashes (ignored by the library, which also accepts an issuer
 * claim with or without a trailing slash).
 *
 * @param string $url
 * @return string
 */
function oidc_normalize_issuer_url($url)
{
	$url = trim((string)$url);
	$url = preg_replace('#/\.well-known/openid-configuration/*$#i', '', $url);
	return rtrim($url, '/');
}

/**
 * Whether the provider settings needed by every flow are set
 */
function oidc_provider_configured()
{
	global $conf;
	return ($conf['OIDC']['issuer_url'] ?? '') !== '' && ($conf['OIDC']['client_id'] ?? '') !== '';
}

/**
 * Create an instance of OpenIDConnectClient with the configured settings
 */
function get_oidc_client() {
	global $conf;
	$config = $conf['OIDC'];
	
	// Create OIDC client
	$oidc = new OpenIDConnectClient(
		oidc_normalize_issuer_url($config['issuer_url'] ?? ''),
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
	$name = is_string($name) ? $name : '';
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
	oidc_log('registration of user "' . $name . '" failed: ' . implode(' / ', $errors));
}

/**
 * Show a message to the user on the next page, for interactive logins only
 * (not through the webservice, whose clients would see it later in the
 * gallery). The message must not contain values from the provider: page
 * messages are not escaped by the templates.
 *
 * Stored as an info: the gallery themes display errors and infos, not
 * warnings.
 *
 * @param string $message
 */
function oidc_user_warning($message)
{
	if (script_basename() == 'ws') {
		return;
	}
	$_SESSION['page_infos'][] = $message;
}

/**
 * Write a message for the administrator in the PHP error log.
 *
 * error_log() and not trigger_error(): never displayed in the page, even with
 * display_errors on. Messages contain values from the provider: control
 * characters are escaped so that they cannot forge log lines.
 *
 * @param string $message
 */
function oidc_log($message)
{
	error_log('OpenIdConnect: ' . addcslashes((string)$message, "\0..\37"));
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
	if (!is_string($sub) || $sub === '') {
		return null;
	}
	$email = $oidc->requestUserInfo('email');
	if (!is_string($email)) {
		$email = '';
	}
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
			//    user is registered without e-mail, oidc_update_user() sets it.
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

	return $row['id'];
}

/**
 * Update the Piwigo user $user_id from the claims of the provider: username,
 * e-mail and groups (if groups management is enabled).
 *
 * Called once the login is accepted. The username and e-mail get the checks
 * of register_user(), which the provider may not enforce (a user may be able
 * to edit these claims): values failing them are logged and not applied.
 */
function oidc_update_user(OpenIDConnectClient $oidc, $user_id)
{
	global $conf;
	$config = $conf['OIDC'];
	$user_id = (int)$user_id;

	$row = oidc_get_user_row($user_id);
	if (empty($row)) {
		return;
	}

	$data = [];

	// Without a usable preferred username claim, the username is not changed
	// (get_preferred_username() falls back to sub, for the registration only)
	$name = null;
	if (empty($config['preferred_username'])) {
		$name = get_preferred_username($oidc);
	} else {
		$claim = $oidc->requestUserInfo($config['preferred_username']);
		if (is_string($claim) && $claim !== '') {
			$name = $claim;
		}
	}
	if (is_string($name) && $name !== $row['username']) {
		$owner = get_userid($name);
		if ($name === '' || trim($name) !== $name || strip_tags($name) !== $name) {
			oidc_log('username "' . $name . '" of user #' . $user_id . ' not applied: invalid username');
			oidc_user_warning(l10n('Your username was not updated from your OpenID Connect account: it is not a valid Piwigo username.'));
		} elseif ($owner !== false && (int)$owner !== $user_id) {
			oidc_log('username "' . $name . '" of user #' . $user_id . ' not applied: already used by user #' . (int)$owner);
			oidc_user_warning(l10n('Your username was not updated from your OpenID Connect account: it is already used by another account.'));
		} else {
			$data[$conf['user_fields']['username']] = pwg_db_real_escape_string($name);
		}
	}

	// An absent or empty e-mail claim keeps the current e-mail
	$email = $oidc->requestUserInfo('email');
	if (is_string($email) && $email !== '' && $email !== (string)$row['email']) {
		$query = '
SELECT COUNT(*) FROM ' . USERS_TABLE . '
  WHERE UPPER(' . $conf['user_fields']['email'] . ') = UPPER(\'' . pwg_db_real_escape_string($email) . '\')
    AND ' . $conf['user_fields']['id'] . ' != ' . $user_id . '
;';
		list($count) = pwg_db_fetch_row(pwg_query($query));
		if (!email_check_format($email)) {
			oidc_log('e-mail "' . $email . '" of user #' . $user_id . ' not applied: invalid e-mail');
			oidc_user_warning(l10n('Your e-mail address was not updated from your OpenID Connect account: it is not a valid e-mail address.'));
		} elseif ($count != 0) {
			oidc_log('e-mail "' . $email . '" of user #' . $user_id . ' not applied: already used by another user');
			oidc_user_warning(l10n('Your e-mail address was not updated from your OpenID Connect account: it is already used by another account.'));
		} else {
			$data[$conf['user_fields']['email']] = pwg_db_real_escape_string($email);
		}
	}

	if (!empty($data)) {
		// mass_updates() does not escape values: they are escaped above
		mass_updates(
			USERS_TABLE,
			['primary' => [$conf['user_fields']['id']], 'update' => array_keys($data)],
			[[$conf['user_fields']['id'] => $user_id] + $data]
		);
	}

	// Groups: synchronized with the groups claim if groups management is
	// enabled. The groups are left untouched if the provider does not return
	// the claim.
	if (!empty($config['manage_groups'])) {
		// 'group_claim' is the legacy name of the setting
		$groups_claim = $config['groups_claim'] ?? $config['group_claim'] ?? '';
		if ($groups_claim === '') {
			$groups_claim = 'groups';
		}

		$groups = $oidc->requestUserInfo($groups_claim);
		if (is_array($groups)) {
			oidc_sync_groups($user_id, $groups);
		}
	}
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

	// The login is accepted: update the user from the provider claims
	oidc_update_user($oidc, $id);

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
		// $service is a global when ws_init.inc.php was already included
		// (pwg.images.uploadAsync, or from a webservice method)
		global $service;
		include_once(PHPWG_ROOT_PATH . 'include/ws_init.inc.php');
		$service->sendResponse(new PwgError(401, 'Session expired, please log in again'));
		exit();
	}

	redirect_auth() or redirect(get_root_url() . 'identification.php');
}
?>