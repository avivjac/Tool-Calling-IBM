from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Literal, TypedDict, NotRequired

IndicatorType = Literal["ip", "url", "domain", "hash"]

class ProviderResult(TypedDict, total=False):
    provider: str
    indicator: str
    indicator_type: IndicatorType
    raw: dict
    verdict: NotRequired[str]
    score: NotRequired[int]


class BaseProvider(ABC):
    """
    בסיס שכל provider יורש ממנו.
    דואג שיהיה לנו API אחיד:
    query(indicator, indicator_type) -> ProviderResult
    """

    name: str                     # שם קצר, למשל "virustotal"
    provider_kind: Literal["api", "db"]

    @abstractmethod
    async def query(
        self,
        indicator: str,
        indicator_type: IndicatorType,
    ) -> ProviderResult:
        """
        מבצע שאילתה לפרוביידר (API/DB וכו')
        ומחזיר תוצאה בפורמט אחיד.
        """
        ...
