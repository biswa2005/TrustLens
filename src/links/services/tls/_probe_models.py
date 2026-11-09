"""Probe wire models. Kept byte-identical to the fetcher copy."""
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

Host = Annotated[str, StringConstraints(min_length=1, max_length=253, pattern=r"^[A-Za-z0-9.\-:\[\]]+$")]


class TLSProbeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    host: Host
    port: Literal[443] = 443
    timeout_budget: float = Field(gt=0.5, le=8.0)
    alpn_protocols: list[Literal["h2", "http/1.1"]] = Field(default=["h2", "http/1.1"], max_length=2)


class TLSProbeResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    host: str
    port: int
    ok: bool
    error_kind: str | None = None
    error_detail: str | None = None
    der_chain_base64: list[str] = Field(default_factory=list, max_length=10)
    ocsp_staple_base64: str | None = None
    limitations: list[str] = Field(default_factory=list, max_length=32)
    negotiated_protocol: str | None = None
    negotiated_cipher: str | None = None
