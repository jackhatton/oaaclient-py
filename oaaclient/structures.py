"""
Copyright 2023 Veza Technologies Inc.

Use of this source code is governed by the MIT
license that can be found in the LICENSE file or at
https://opensource.org/licenses/MIT.
"""

from collections.abc import MutableMapping
from typing import Iterator, TypeVar, cast, Any

KT = TypeVar("KT")
VT = TypeVar("VT")


class CaseInsensitiveDict(MutableMapping[KT, VT]):
    """Case Insensitive Key Dictionary

    Dictionary like object with case insensitive keys for types that support `.lower()` such as strings.

    Keys do not have to be strings, in the case where the key type does not support `.lower()` such as integers the
    value is used as is.

    Example:
        >>> from oaaclient.structures import CaseInsensitiveDict
        >>> x = CaseInsensitiveDict()
        >>> x["User"] = "value"
        >>> x.get("user")
        'value'
        >>> "USER" in x
        True
        >>> print(x)
        {'user': 'value'}
        >>> x
        CaseInsensitiveDict({'user': 'value'})

    """

    def __init__(self) -> None:
        self.data = dict[KT, VT]()

    def _case_insensitive(self, key: KT) -> KT:
        if hasattr(key, "lower") and callable(getattr(key, "lower")):
            return cast(Any, key).lower()
        return key

    def __getitem__(self, key: KT) -> VT:
        return self.data[self._case_insensitive(key)]

    def __setitem__(self, key: KT, value: VT) -> None:
        self.data[self._case_insensitive(key)] = value

    def __delitem__(self, key: KT) -> None:
        del self.data[self._case_insensitive(key)]

    def __iter__(self) -> Iterator[KT]:
        return iter(self.data)

    def __len__(self) -> int:
        return len(self.data)

    def __str__(self) -> str:
        return str(self.data)

    def __repr__(self) -> str:
        return f"CaseInsensitiveDict({self.data!r})"
