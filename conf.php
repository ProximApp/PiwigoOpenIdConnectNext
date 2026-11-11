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

return [
    // 'issuer_url' => '',
    // 'client_id' => '',
    // 'client_secret' => '',
    // 'scope' => '',
    // 'preferred_username' => '',
    // 'manage_groups' => false,
    // 'groups_claim' => '',
    // 'proxy' => '',
    // 'verify_host' => false,
    // 'verify_peer' => false,
    // 'authparam' => '',
    // 'register_new_users' => false,
    // 'redirect_new_to_profile' => false,
    // 'notify_admins_on_register' => false,
    // 'notify_user_on_register' => false,
    // 'authorization_code_flow' => false,
    // 'password_flow' => false,
    // 'password_reset_url' => '',
    // 'registration_url' => '',
    // Allow webmasters to log in with their local Piwigo password through
    // identification.php?oidc_local=1 while a flow is enabled (never through the API)
    // Redirect URL sent to the provider, default: <Piwigo URL>/plugins/OpenIdConnect/auth.php
    // Set it when Piwigo is behind a reverse proxy which changes the URL
    // 'redirect_url' => '',
    // 'local_webmaster_login' => false,
    // Run the finalize_login checks of other plugins (2FA, account lockout...)
    // for OpenID Connect logins too
    // 'apply_login_checks' => true,
    // Client IDs, other than client_id, whose access tokens are accepted by the
    // pwg.session.login_oidc API method (e.g. a mobile application registered
    // as a separate client with the same provider).
    // 'api_trusted_client_ids' => [],
];

?>