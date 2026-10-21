import re

from ldap3.core.exceptions import LDAPInvalidDnError
from ldap3.utils.dn import parse_dn

_BARE_GROUP = re.compile(r'[^\s&|()"]+')


def _tokenize(expression: str):
    tokens = []
    pos = 0
    while pos < len(expression):
        if expression[pos].isspace():
            pos += 1
        elif expression.startswith(('&&', '||'), pos):
            tokens.append(expression[pos : pos + 2])
            pos += 2
        elif expression[pos] in '()':
            tokens.append(expression[pos])
            pos += 1
        elif expression[pos] == '"':
            end = expression.find('"', pos + 1)
            if end < 0 or end == pos + 1:
                raise ValueError('OAUTH_CLIENT_AD_GROUPS has an empty or unclosed group name')
            tokens.append(('group', expression[pos + 1 : end]))
            pos = end + 1
        else:
            match = _BARE_GROUP.match(expression, pos)
            if not match:
                raise ValueError(f'OAUTH_CLIENT_AD_GROUPS has an invalid character at position {pos}')
            tokens.append(('group', match.group()))
            pos = match.end()
    return tokens


def parse_group_policy(expression: str):
    tokens = _tokenize(expression)

    index = 0

    def primary():
        nonlocal index
        if index < len(tokens) and tokens[index] == '(':
            index += 1
            node = or_expression()
            if index >= len(tokens) or tokens[index] != ')':
                raise ValueError('OAUTH_CLIENT_AD_GROUPS has unbalanced parentheses')
            index += 1
            return node
        if index < len(tokens) and isinstance(tokens[index], tuple):
            node = tokens[index]
            index += 1
            return node
        raise ValueError('OAUTH_CLIENT_AD_GROUPS expects a group name')

    def and_expression():
        nonlocal index
        node = primary()
        while index < len(tokens) and tokens[index] == '&&':
            index += 1
            node = ('and', node, primary())
        return node

    def or_expression():
        nonlocal index
        node = and_expression()
        while index < len(tokens) and tokens[index] == '||':
            index += 1
            node = ('or', node, and_expression())
        return node

    policy = or_expression()
    if index != len(tokens):
        raise ValueError('OAUTH_CLIENT_AD_GROUPS has an unexpected token')
    return policy


def parse_base_dn(value: str):
    try:
        rdns = parse_dn(value, strip=True)
    except LDAPInvalidDnError as exc:
        raise ValueError('OAUTH_CLIENT_AD_BASE_DN must be a valid DN') from exc
    if not rdns or any(not attribute or not name for attribute, name, _ in rdns):
        raise ValueError('OAUTH_CLIENT_AD_BASE_DN must be a valid DN')
    return tuple((attribute.casefold(), name.casefold(), separator) for attribute, name, separator in rdns)


def _member_groups(member_of, base_dn):
    full_dns = set()
    # Short operands match the first CN; use a full DN to distinguish duplicate CNs.
    common_names = set()
    for group in member_of:
        if base_dn is None:
            full_dns.add(group.strip().casefold())
        try:
            rdns = parse_dn(group, strip=True)
        except LDAPInvalidDnError:
            continue
        if base_dn is not None:
            parts = tuple((attribute.casefold(), name.casefold(), separator) for attribute, name, separator in rdns)
            if len(parts) <= len(base_dn) or parts[-len(base_dn) :] != base_dn or parts[-len(base_dn) - 1][2] != ',':
                continue
            full_dns.add(group.strip().casefold())
        if rdns and rdns[0][0].casefold() == 'cn':
            common_names.add(rdns[0][1].casefold())
    return full_dns, common_names


def group_policy_allows(policy, member_of, base_dn=None) -> bool:
    if not isinstance(member_of, list) or not all(isinstance(group, str) for group in member_of):
        return False

    full_dns, common_names = _member_groups(member_of, base_dn)

    def matches(node):
        if node[0] == 'group':
            name = node[1].casefold()
            return name in full_dns or ('=' not in name and name in common_names)
        if node[0] == 'and':
            return matches(node[1]) and matches(node[2])
        return matches(node[1]) or matches(node[2])

    return matches(policy)
