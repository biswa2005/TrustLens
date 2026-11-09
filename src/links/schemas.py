from pydantic import BaseModel, Field
from typing import Annotated, Literal

class AnalyseRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)
    skip_third_party_reputation: bool = False

class FullScreenRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)
    mode: Literal["full"] = "full"

class HostOnlyScreenRequest(BaseModel):
    host: str = Field(min_length=1, max_length=253)
    mode: Literal["host_only"]

ScreenRequest = Annotated[FullScreenRequest | HostOnlyScreenRequest, Field(discriminator="mode")]

