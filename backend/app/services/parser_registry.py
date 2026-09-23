from __future__ import annotations

from collections.abc import Callable
from typing import Any


# A vendor parser receives raw configuration text and returns
# normalized security parameters.
VendorParser = Callable[[str], dict[str, Any]]


class ParserRegistry:
    """
    Registry for vendor-specific configuration parsers.

    Vendor detection and parser selection are deliberately kept
    separate. The detector identifies the vendor; this registry
    resolves the corresponding parser.
    """

    def __init__(self) -> None:
        self._parsers: dict[str, VendorParser] = {}

    def register(
        self,
        vendor: str,
        parser: VendorParser,
    ) -> None:
        """
        Register or replace a parser for a vendor.
        """

        normalized_vendor = vendor.strip().lower()

        if not normalized_vendor:
            raise ValueError("Vendor name cannot be empty")

        self._parsers[normalized_vendor] = parser

    def get(
        self,
        vendor: str | None,
    ) -> VendorParser | None:
        """
        Return the parser registered for a vendor.
        """

        if not vendor:
            return None

        return self._parsers.get(
            vendor.strip().lower()
        )

    def has(
        self,
        vendor: str | None,
    ) -> bool:
        """
        Check whether a parser exists for a vendor.
        """

        return self.get(vendor) is not None

    def supported_vendors(self) -> list[str]:
        """
        Return registered vendors.
        """

        return sorted(self._parsers.keys())


# Global application registry.
parser_registry = ParserRegistry()