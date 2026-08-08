"""Configuração do engine e sessão do banco de dados."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from siem.persistence.models import Base


def create_db_engine(database_url: str) -> Engine:
    """Cria o engine SQLAlchemy e garante que as tabelas existam.

    Args:
        database_url: string de conexão SQLAlchemy (ex: 'sqlite:///./siem.db',
            'postgresql://user:pass@host/db').

    Returns:
        Engine configurado, com as tabelas já criadas se não existirem.
    """
    connect_args = {"check_same_thread": False} if database_url.startswith("sqlite") else {}
    engine = create_engine(database_url, connect_args=connect_args)
    Base.metadata.create_all(engine)
    return engine


def create_session_factory(database_url: str) -> sessionmaker[Session]:
    """Cria uma fábrica de sessões vinculada ao engine do banco configurado."""
    engine = create_db_engine(database_url)
    return sessionmaker(bind=engine, expire_on_commit=False)


@contextmanager
def session_scope(session_factory: sessionmaker[Session]) -> Iterator[Session]:
    """Fornece uma sessão transacional: commit em sucesso, rollback em erro.

    Uso:
        with session_scope(factory) as session:
            session.add(record)
    """
    session = session_factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()