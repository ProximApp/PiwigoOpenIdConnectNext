# Piwigo OpenID Connect plugin - Next version

OpenID Connect is a Piwigo plugin which allows single sign-on logins using the
OpenID Connect protocol. The protocol utilizes both the OpenID Connect Core and
the OpenID Connect Discovery specifications. The plugin supports both the
authorization code flow, as well as the (legacy) resource owner credentials
flow, otherwise known as the password flow. Although legacy and recommended
against, by enabling this flow, login through the Piwigo webservice API is
enabled.

Special thanks to jumbojett for the OpenID Connect library used in this plugin.

This project is a fork of [jasperweyne/PiwigoOpenIdConnect](https://github.com/jasperweyne/PiwigoOpenIdConnect) updated to work with newer versions of Piwigo and PHP. Special thanks to jasperweyne for the original Piwigo plugin.

## License

This project is covered by the Apache 2.0 License, please refer to the LICENSE
file enclosed.

## Install

Requirements: PHP 7.4 or later. Tested with Piwigo 16.5 on PHP 8.4.

The plugin can be installed easily from [Piwigo extension library](https://piwigo.org/ext/index.php?eid=1049)

Alternatively, you can download a release and
unzip it to the /plugins folder within your Piwigo installation. Enable the
plugin from Piwigo (it should be visible), and configure the plugin through the
admin. Test that your installation is functional before enabling a flow.

## Configuration

1. At your provider, create a confidential client (with a client secret) and
   register the redirect URL displayed in the *Authorization Code Flow*
   section of the plugin admin page:
   `https://<piwigo>/plugins/OpenIdConnect/auth.php`.
2. In the plugin admin page, enter the **Issuer URL** (the base URL of the
   provider, without `/.well-known/openid-configuration`: the plugin finds the
   provider settings there automatically), the client ID and the client secret.
3. **Save the settings**, then use *Test authorization code flow*. The tests use
   the saved settings, not the values being edited.
4. Use *Create user with authorization code flow* to create your own account,
   give it the webmaster status in Piwigo, and only then enable the
   authorization code flow (or enable the webmaster local login, see below).

### Pocket ID

Tested with [Pocket ID](https://pocket-id.org) 1.16:

| Setting            | Value                                                     |
|--------------------|-----------------------------------------------------------|
| Issuer URL         | `https://login.example.com` (your Pocket ID URL)          |
| Client             | *OIDC Clients* > *Add OIDC Client*, not public, callback URL `https://<piwigo>/plugins/OpenIdConnect/auth.php` |
| Scopes             | `openid profile email groups`                             |
| Preferred username | `preferred_username`                                      |
| Groups claim       | `groups` (with *Enable groups management*)                |
| Flow               | Authorization code flow only: Pocket ID does not support the resource owner credentials (password) flow |

Known limitations with Pocket ID 1.16:

- a user *disabled* in Pocket ID can still log in, and existing sessions stay
  valid, because Pocket ID keeps issuing tokens for disabled users. Delete the
  user in Pocket ID to revoke their access;
- `api_trusted_client_ids` has no effect (see *Login through the API*).

## Change the configuration from conf.php

If OIDC is enabled, and you need to login using a non-oidc account, you can change the value of `authorization_code_flow` or
`password_flow` to false in conf.php file.



## Local accounts when a flow is enabled

When a flow is enabled, local Piwigo passwords are disabled everywhere (login page, `pwg.session.login`,
`pwg.images.uploadAsync`), and sessions not opened with OpenID Connect are logged out. These still work:

- API keys (`X-PIWIGO-API` header, or as credentials of `pwg.session.login`);
- authentication keys (`?auth=` links sent by e-mail).

Users logged in with OpenID Connect can manage their API keys from their profile. An API key keeps working even if
the user is removed from the provider: revoke it in Piwigo too.

As a fallback, the *Allow webmasters to log in with their local password* option lets webmasters log in with their
local password on `identification.php?oidc_local=1` only (never through the API).

## Login checks of other plugins

Like the Piwigo login, an OpenID Connect login runs the `finalize_login` checks of other plugins (two-factor
authentication, account lockout...). A two-factor authentication plugin expecting a code in the Piwigo login form will
block OpenID Connect logins: in that case, or if multi-factor authentication is already handled by your provider,
disable *Apply the login checks of other plugins to OpenID Connect users*.

## Login through the API

The `pwg.session.login_oidc` webservice method logs a user in using an OpenID Connect access token. It is only available when one of the flows is enabled.

To prevent tokens issued to other applications from being replayed, the token is checked with the provider's token introspection endpoint (RFC 7662): it must be active and issued to the plugin `client_id`, or to one of the clients listed in `api_trusted_client_ids` in conf.php. Providers without an introspection endpoint cannot be used for API login. Some providers only let a client introspect its own tokens (Pocket ID for example): `api_trusted_client_ids` has no effect with them, only tokens issued to the plugin `client_id` are accepted.
