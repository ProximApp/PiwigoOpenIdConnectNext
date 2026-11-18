{if $OIDC_LINKED}
  <p>{'Your account is linked to an OpenID Connect account: you can log in with it.'|translate}</p>
  {if $OIDC_CAN_UNLINK}
  <p><a class="btn btn-main button" href="{$U_OIDC_UNLINK|escape:html}">{'Unlink my OpenID Connect account'|translate}</a></p>
  {else}
  <p><i>{'This link cannot be removed while OpenID Connect login is enforced: you could no longer log in.'|translate}</i></p>
  {/if}
{else}
  <p>{'Link your account to your OpenID Connect account, to log in with it.'|translate}</p>
  <p><a class="btn btn-main button" href="{$U_OIDC_LINK|escape:html}">{'Link my OpenID Connect account'|translate}</a></p>
{/if}
