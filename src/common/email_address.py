"""Closed ASCII mailbox syntax shared by every notification boundary."""

from __future__ import annotations


_ATEXT = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&'*+-/=?^_`{|}~"
)
_DOMAIN = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-"
)
_ALNUM = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
)


def is_valid_local_part(value: object) -> bool:
    """Accept an unquoted ASCII dot-atom local-part only."""

    if type(value) is not str or not 1 <= len(value) <= 64 or not value.isascii():
        return False
    if value.startswith(".") or value.endswith(".") or ".." in value:
        return False
    return all(character == "." or character in _ATEXT for character in value)


def is_valid_mailbox(value: object) -> bool:
    """Accept one bounded addr-spec; display names, literals and Unicode are excluded."""

    if type(value) is not str or not 3 <= len(value) <= 254 or not value.isascii():
        return False
    if value.count("@") != 1:
        return False
    local_part, domain = value.rsplit("@", 1)
    labels = domain.split(".")
    if (
        not is_valid_local_part(local_part)
        or not 3 <= len(domain) <= 253
        or len(labels) < 2
    ):
        return False
    return all(
        1 <= len(label) <= 63
        and label[0] in _ALNUM
        and label[-1] in _ALNUM
        and all(character in _DOMAIN for character in label)
        for label in labels
    )
