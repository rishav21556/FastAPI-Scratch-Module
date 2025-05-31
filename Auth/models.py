from pydantic import BaseModel
from sqlmodel import Field,  SQLModel

class User(SQLModel, table=True):
    username: str = Field(primary_key=True)
    password: str
    isAdmin : bool = Field(default=False)