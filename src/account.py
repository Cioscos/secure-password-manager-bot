from dataclasses import dataclass, field
import uuid
from typing import Optional


@dataclass
class Account:
    id: str = field(init=False)
    name: Optional[str] = field(init=False)
    user_name: Optional[str] = field(init=False)
    password: Optional[str] = field(init=False)

    def __post_init__(self) -> None:
        self.id = str(uuid.uuid4())
        self.name = None
        self.user_name = None
        self.password = None
