<?php
/*
   Copyright 2021 Jasper Weyne

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

require_once(PHPWG_ROOT_PATH . 'include/common.inc.php');
require_once(OIDC_PATH . 'oidc.php');

/**
 * Check that an access token has been issued to this Piwigo instance
 * (or to an explicitly trusted client), using token introspection (RFC 7662).
 *
 * Without this check, any access token issued by the provider to *another*
 * client (any third party application relying on the same provider) could be
 * replayed to log in as the token owner.
 *
 * @return string|null the `sub` of the token owner if the token is valid, null otherwise
 */
function oidc_validate_api_token($oidc, $access_token)
{
    global $conf;
    $config = $conf['OIDC'];

    $allowed_clients = array_filter(array_merge(
        [$config['client_id'] ?? ''],
        (array)($config['api_trusted_client_ids'] ?? [])
    ));

    $introspection = $oidc->introspectToken($access_token, 'access_token');

    if (!is_object($introspection) || empty($introspection->active)) {
        return null;
    }

    // Check expiration, in case the provider does not do it
    if (isset($introspection->exp) && $introspection->exp < time()) {
        return null;
    }

    // The token must have been issued to an allowed client
    $audiences = [];
    if (isset($introspection->client_id)) {
        $audiences[] = $introspection->client_id;
    }
    if (isset($introspection->azp)) {
        $audiences[] = $introspection->azp;
    }
    if (isset($introspection->aud)) {
        $audiences = array_merge($audiences, (array)$introspection->aud);
    }
    if (empty(array_intersect($audiences, $allowed_clients))) {
        return null;
    }

    return $introspection->sub ?? '';
}

/**
 * API method
 * Tries to login the user using an OIDC token 
 * @param mixed[] $params
 *    @option string access_token
 */
function api_login($params, &$service)
{
    // API login is only available if an OpenID Connect flow is enabled
    if (!can_authorization_grant() && !can_resource_owner_credentials_grant()) {
        return new PwgError(403, 'OpenID Connect login is disabled');
    }

    $access_token = stripslashes($params['access_token']);

    try {
        // Create OIDC service object
        $oidc = get_oidc_client();

        // Make sure the token has been issued for this client
        $introspected_sub = oidc_validate_api_token($oidc, $access_token);
        if ($introspected_sub === null) {
            return new PwgError(401, 'Invalid access token');
        }

        $oidc->setAccessToken($access_token);

        // The token owner must be the user returned by the userinfo endpoint
        if ($introspected_sub !== '' && $introspected_sub !== $oidc->requestUserInfo('sub')) {
            return new PwgError(401, 'Invalid access token');
        }

        // Create token object from params
        $tokens = new stdClass();
        $tokens->access_token = $access_token;
        if (oidc_login($oidc, $tokens, false))
        {
            return true;
        }
    } catch (\Exception $e) {
        // Most likely: the provider does not expose an introspection endpoint
        return new PwgError(401, 'Invalid access token');
    }

    return new PwgError(401, 'Invalid access token');
}

?>