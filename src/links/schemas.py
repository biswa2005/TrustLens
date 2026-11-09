from pydantic import BaseModel, Field

class AnalyseRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)
    skip_third_party_reputation: bool = False

