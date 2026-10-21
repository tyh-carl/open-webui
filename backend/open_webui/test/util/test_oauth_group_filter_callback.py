from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from urllib.parse import parse_qs, urlsplit

import pytest
from open_webui.utils.oauth_group_filter import parse_group_policy
from starlette.responses import Response


@pytest.mark.asyncio
async def test_denied_oidc_login_never_looks_up_user(monkeypatch):
    from open_webui.utils import oauth

    manager = oauth.OAuthManager.__new__(oauth.OAuthManager)
    manager.oidc_group_policy = parse_group_policy('ALLOWED')
    manager.oidc_group_base_dn = None
    claims = {
        'sub': 'subject',
        'email': 'user@example.com',
        'name': 'User',
        'member_of': ['CN=OTHER,CN=Users,DC=EMSD,DC=HKSARG'],
    }
    client = SimpleNamespace(
        authorize_access_token=AsyncMock(return_value={'userinfo': claims}),
        userinfo=AsyncMock(return_value=claims),
    )
    manager.get_client = lambda provider: client
    monkeypatch.setitem(oauth.OAUTH_PROVIDERS, 'oidc', {})
    request = SimpleNamespace(
        base_url='http://backend/',
        app=SimpleNamespace(state=SimpleNamespace(config=SimpleNamespace(WEBUI_URL='http://frontend'))),
    )

    with patch.object(oauth.Users, 'get_user_by_oauth_sub') as lookup:
        result = await manager.handle_callback(request, 'oidc', Response())

    lookup.assert_not_called()
    assert result.status_code == 307
    redirect = urlsplit(result.headers['location'])
    assert f'{redirect.scheme}://{redirect.netloc}{redirect.path}' == 'http://frontend/auth'
    assert parse_qs(redirect.query)['error'] == [oauth.ERROR_MESSAGES.ACCESS_PROHIBITED]
