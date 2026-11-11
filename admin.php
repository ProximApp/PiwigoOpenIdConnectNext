<?php
/*
   Copyright 2020 Jasper Weyne

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

defined('OIDC_PATH') or die('Hacking attempt!');

// CSRF protection: every form of this page must carry a valid pwg_token
if (!empty($_POST))
{
	check_pwg_token();
}

// Authorization flow forms
if (isset($_POST['authorization_create']))
{
	$_SESSION[OIDC_SESSION . '_auth'] = 'create';
	redirect(OIDC_PATH . 'auth.php'); 
}

if (isset($_POST['authorization_test']))
{
	$_SESSION[OIDC_SESSION . '_auth'] = 'test';
	redirect(OIDC_PATH . 'auth.php'); 
}

// Password flow forms
if (isset($_POST['password_test']) || isset($_POST['password_create']))
{
	// Build a token request
	$oidc = get_oidc_client();
	// Piwigo addslashes() the request parameters, the provider needs the raw values
	$oidc->addAuthParam([
		'username' => stripslashes($_POST['password_test_user'] ?? ''),
		'password' => stripslashes($_POST['password_test_pass'] ?? ''),
	]);

	// Try to perform token request
	try {
		$response = $oidc->requestResourceOwnerToken(true);
		if (!isset($response->access_token)) {
			$page['errors'][] = htmlspecialchars(($response->error ?? 'unknown_error') . (isset($response->error_description) ? ': ' . $response->error_description : ''));
		} else {
			// Token request succeeded, store token in $oidc
			$oidc->setAccessToken($response->access_token);

			// If userinfo point is inaccessible, show error
			if (null === $oidc->requestUserInfo('sub')) {
				$page['errors'][] = l10n('Server did not return user info');
			} else if (isset($_POST['password_create'])) {
				// User creation flow
				$user_id = oidc_retrieve($oidc, true);
				if ($user_id !== null) {
					$page['infos'][] = l10n('User added to Piwigo!');
				} else {
					$page['errors'][] = l10n('A problem occurred during user registration.');
				}
			} else {
				$page['infos'][] = l10n('Resource owner credentials flow successful!');
			}
		}
	} catch (\Exception $e) {
		// Catch all
		$page['errors'][] = htmlspecialchars($e->getMessage());
	}
}

// Save settings form
if (isset($_POST['save_config']))
{
	// Piwigo addslashes() the request parameters: store the raw values
	$text = function ($name) {
		return trim(stripslashes($_POST[$name] ?? ''));
	};
	$conf['OIDC'] = [
		'issuer_url' => $text('issuer_url'),
		'client_id' => $text('client_id'),
		'client_secret' => $text('client_secret'),
		// We want to save password_test_user and password_test_pass
		// to prevent PHP from raising an error
		// We reset the two values as they may contains sensitive data
		'password_test_user' => '',
		'password_test_pass' => '',
		'scope' => $text('scope'),
		'preferred_username' => $text('preferred_username'),
		'manage_groups' => isset($_POST['manage_groups']),
		'groups_claim' => $text('groups_claim'),
		'proxy' => $text('proxy'),
		'verify_host' => isset($_POST['verify_host']),
		'verify_peer' => isset($_POST['verify_peer']),
		'authparam' => $text('authparam'),
		'register_new_users' => isset($_POST['register_new_users']),
		'redirect_new_to_profile' => isset($_POST['redirect_new_to_profile']),
		'notify_admins_on_register' => isset($_POST['notify_admins_on_register']),
		'notify_user_on_register' => isset($_POST['notify_user_on_register']),
		'authorization_code_flow' => isset($_POST['authorization_code_flow']),
		'password_flow' => isset($_POST['password_flow']),
		'password_reset_url' => $text('password_reset_url'),
		'registration_url' => $text('registration_url'),
		'local_webmaster_login' => isset($_POST['local_webmaster_login']),
		'apply_login_checks' => isset($_POST['apply_login_checks']),
	];
	if ($conf['OIDC']['authparam'] !== '' && !is_array(json_decode($conf['OIDC']['authparam'], true))) {
		$page['errors'][] = l10n('Authentication parameters must be a JSON object, they are ignored.');
	}

	conf_update_param('OIDC', $conf['OIDC']);
	$page['infos'][] = l10n('Settings saved.');
}

// General warnings
if (oidc_enforced() && empty($_SESSION[OIDC_SESSION]) && !oidc_local_session_allowed($user)) {
	$page['warnings'][] = l10n('An OpenID Connect flow is enabled but you are not logged in with OpenID Connect: you will be logged out at the next page load. Make sure an OpenID Connect account has webmaster access rights, or enable the webmaster local login.');
}
if (!$conf['allow_user_registration'] && $conf['OIDC']['register_new_users']) {
	$page['warnings'][] = l10n('User registration is disabled in the Piwigo settings. This behaviour will be overridden by this plugin.');
}

// Render page
$template->assign($conf['OIDC']);
$template->assign([
	'redirect_url' => oidc_redirect_url(),
	'PWG_TOKEN' => get_pwg_token(),
	'local_login_url' => get_absolute_root_url() . 'identification.php?oidc_local=1',
]);

$template->set_filename('oidc_config', realpath(OIDC_PATH . 'template/config.tpl'));
$template->assign_var_from_handle('ADMIN_CONTENT', 'oidc_config');
?>