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

The plugin can be installed easily from [Piwigo extension library](https://piwigo.org/ext/index.php?eid=1049)

Alternatively, you can download a release and
unzip it to the /plugins folder within your Piwigo installation. Enable the
plugin from Piwigo (it should be visible), and configure the plugin through the
admin. Test that your installation is functional before enabling a flow.

## Change the configuration from conf.php

If OIDC is enabled, and you need to login using a non-oidc account, you can change the value of `authorization_code_flow` or
`password_flow` to false in conf.php file.
