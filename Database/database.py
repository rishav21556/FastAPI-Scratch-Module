from dotenv import load_dotenv
from pathlib import Path
import os
from pydantic import PostgresDsn
from sqlalchemy.ext.asyncio import (
    AsyncAttrs,
    async_sessionmaker,
    create_async_engine,
    AsyncSession,
)
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import DeclarativeBase
from fastapi import HTTPException, status

load_dotenv(dotenv_path=Path('.env'))

# load db configurations
DBUSER = os.getenv('DBUSER')
DBPASSWORD= os.getenv('DBPASSWORD')
DBNAME= os.getenv('DBNAME')
PASSWORDKEY=os.getenv('PASSWORDKEY')
DBHOST=os.getenv('DBHOST')
DBPORT=os.getenv('DBPORT')

PG_URL = f"postgresql+asyncpg://{DBUSER}:{DBPASSWORD}@{DBHOST}:{DBPORT}/{DBNAME}"

engine = create_async_engine(PG_URL, future=True, echo=True)

SessionFactory = async_sessionmaker(engine, autoflush=False, expire_on_commit=False)

async def load_db():
    db = SessionFactory()
    try:
        yield db
    finally:
        await db.close()

class Base(AsyncAttrs, DeclarativeBase):
    async def save(self, db: AsyncSession):
        try: 
            db.add(self)
            return await db.commit()
        except SQLAlchemyError as ex:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=repr(ex)
            ) from ex
        
    @classmethod
    async def find_by_id(cls, db:AsyncSession, id:str):
        query = select(cls).where(cls.id==id)
        result = await db.execute(query)
        return result.scalars().first()