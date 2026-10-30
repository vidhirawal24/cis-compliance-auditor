"""Phase 2 proposed request extensions; shared review remains pending."""
from pydantic import BaseModel, ConfigDict, Field, field_validator
from .models import Role

class StrictBody(BaseModel):
    model_config = ConfigDict(extra="forbid")


class InviteBody(StrictBody):
    email: str = Field(min_length=3, max_length=254)
    role: Role

    @field_validator("email")
    @classmethod
    def email_shape(cls, value):
        value = value.strip().lower()
        if value.count("@") != 1 or any(c.isspace() for c in value) or "." not in value.split("@")[1]:
            raise ValueError("Invalid email")
        return value


class AcceptBody(StrictBody):
    token: str = Field(min_length=40, max_length=128)


class MemberUpdate(StrictBody):
    role: Role
    active: bool


class ReferenceBody(StrictBody):
    label: str = Field(min_length=1, max_length=200)


