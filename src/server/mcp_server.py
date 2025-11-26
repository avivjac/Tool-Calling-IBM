from __future__ import annotations
from typing import List

from mcp.server.fastmcp import FastMCP

from .providers.tool-base import IndicatorType, BaseProvider
from .providers.API_tools.virustotal import VirusTotalProvider
from .providers.API_tools.alien_vault_otx import AlienVaultOTXProvider
from .providers.API_tools.urlscan_io import URLScanIOProvider
from .providers.API_tools.xforce import XForceProvider

from .providers.DB-tools.abuseipdb import AbuseIPDBProvider
from .providers.db_tools.bron import BRONProvider
from .providers.db_tools.nist import NISTProvider


mcp = FastMCP("Threat Intel MCP Server", json_response=True)

# --- יצירת אינסטנסים של כל ה-providers ---

PROVIDERS: List[BaseProvider] = [
    VirusTotalProvider(),
    AlienVaultOTXProvider(),
    URLScanIOProvider(),
    XForceProvider(),
    AbuseIPDBProvider(),
    BRONProvider(),
    NISTProvider(),
]


# --- MCP TOOLS ---


@mcp.tool()
async def query_provider(
    provider_name: str,
    indicator: str,
    indicator_type: IndicatorType = "ip",
):
    """
    שאילתה לפרוביידר אחד ספציפי.
    """
    for provider in PROVIDERS:
        if provider.name == provider_name:
            return await provider.query(indicator, indicator_type)

    raise ValueError(f"Unknown provider: {provider_name}")


@mcp.tool()
async def query_all_providers(
    indicator: str,
    indicator_type: IndicatorType = "ip",
):
    """
    שאילתה לכל הפרוביידרים במקביל ומאחדת את התוצאות.
    """
    results = []

    for provider in PROVIDERS:
        try:
            res = await provider.query(indicator, indicator_type)
            results.append(res)
        except Exception as e:
            results.append(
                {
                    "provider": provider.name,
                    "indicator": indicator,
                    "indicator_type": indicator_type,
                    "error": str(e),
                }
            )

    return results


if __name__ == "__main__":
    # לפיתוח נוח – HTTP עם inspector
    mcp.run(transport="streamable-http")
    # אח"כ, אם תרצה stdio בשביל Agent/Claude, אפשר להחליף:
    # mcp.run(transport="stdio")
