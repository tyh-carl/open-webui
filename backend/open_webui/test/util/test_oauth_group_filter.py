import pytest
from open_webui.utils.oauth_group_filter import group_policy_allows, parse_base_dn, parse_group_policy


def dn(name):
    return f'CN={name},CN=Users,DC=EMSD,DC=HKSARG'


POLICY = (
    '"RANKGROUP_DIRECTORATE"||'
    '(("RANK_EAE_TS"||"RANK_EAE_RS"||"RANK_AE(N)_TS"||"RANK_AE(N)_RS")&&'
    '("EMSD_TS_ESB1_BTSD"||"EMSD_TS_ESB2_GESD"||"EMSD_TS_ESB1_SVSD_VESDVTS"))'
)


@pytest.mark.parametrize(
    ('groups', 'allowed'),
    [
        (['RANKGROUP_DIRECTORATE'], True),
        (['RANK_AE(N)_TS', 'EMSD_TS_ESB2_GESD'], True),
        (['RANK_EAE_RS', 'EMSD_TS_ESB1_SVSD_VESDVTS'], True),
        (['RANK_AE(N)_TS'], False),
        (['EMSD_TS_ESB2_GESD'], False),
        (['RANK_AE(N)_TS_EXTRA', 'EMSD_TS_ESB2_GESD'], False),
    ],
)
def test_policy_matches_ad_common_names(groups, allowed):
    assert group_policy_allows(parse_group_policy(POLICY), [dn(group) for group in groups]) is allowed


def test_full_dn_operand_and_operator_precedence():
    policy = parse_group_policy(f'"{dn("RANK_AE(N)_TS")}"||B&&C')
    assert group_policy_allows(policy, [dn('RANK_AE(N)_TS')])
    assert not group_policy_allows(policy, [dn('B')])
    assert group_policy_allows(policy, [dn('B'), dn('C')])


def test_base_dn_restricts_short_names_and_full_dns():
    base_dn = parse_base_dn('cn=Users,dc=EMSD,dc=HKSARG')
    inside = dn('RANK_AE(N)_TS')
    outside = 'CN=RANK_AE(N)_TS,OU=Other,DC=EMSD,DC=HKSARG'
    nested = 'CN=RANK_AE(N)_TS,OU=Teams,CN=Users,DC=EMSD,DC=HKSARG'

    assert group_policy_allows(parse_group_policy('"RANK_AE(N)_TS"'), [inside], base_dn)
    assert group_policy_allows(parse_group_policy('"RANK_AE(N)_TS"'), [nested], base_dn)
    assert not group_policy_allows(parse_group_policy('"RANK_AE(N)_TS"'), [outside], base_dn)
    assert not group_policy_allows(parse_group_policy(f'"{outside}"'), [outside], base_dn)
    assert not group_policy_allows(parse_group_policy('"RANK_AE(N)_TS"'), [inside], parse_base_dn('DC=OTHER,DC=HKSARG'))


def test_base_dn_does_not_treat_multivalued_rdn_as_subtree():
    base_dn = parse_base_dn('OU=Users,DC=EMSD,DC=HKSARG')
    group = 'CN=TARGET+OU=Users,DC=EMSD,DC=HKSARG'
    assert not group_policy_allows(parse_group_policy('TARGET'), [group], base_dn)


@pytest.mark.parametrize('base_dn', ['', 'Users', 'CN=Users,DC=', 'CN=Users,'])
def test_invalid_base_dn_is_rejected(base_dn):
    with pytest.raises(ValueError, match='OAUTH_CLIENT_AD_BASE_DN'):
        parse_base_dn(base_dn)


@pytest.mark.parametrize('member_of', [None, 'RANKGROUP_DIRECTORATE', [], [None]])
def test_missing_or_invalid_member_of_is_denied(member_of):
    assert not group_policy_allows(parse_group_policy(POLICY), member_of)


@pytest.mark.parametrize(
    'expression',
    ['', 'A&&', '(A||B', 'A||B)', 'A|B', 'A B', '()', '"A', '""'],
)
def test_invalid_policy_is_rejected(expression):
    with pytest.raises(ValueError, match='OAUTH_CLIENT_AD_GROUPS'):
        parse_group_policy(expression)
