{if $OIDC_LINKED}
  <p>{'Your account is linked to an OpenID Connect account: you can log in with it.'|translate}</p>
  {if $OIDC_ENFORCED}
  <p><i>{'If you unlink it, you will be logged out and will no longer be able to log in to this account.'|translate}</i></p>
  {/if}
  <p><a class="btn btn-main button" href="{$U_OIDC_UNLINK|escape:html}">{'Unlink my OpenID Connect account'|translate}</a></p>
{else}
  <p>{'Link your account to your OpenID Connect account, to log in with it.'|translate}</p>
  <p><a class="btn btn-main button" href="{$U_OIDC_LINK|escape:html}">{'Link my OpenID Connect account'|translate}</a></p>
{/if}
