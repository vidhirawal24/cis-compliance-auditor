from contextlib import contextmanager
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool
from .settings import get_settings


def engine(migration=False):
    s = get_settings()
    url = s.migration_database_url if migration and s.migration_database_url else s.database_url
    return create_engine(url.get_secret_value(), poolclass=NullPool, hide_parameters=True,
                         connect_args={"prepare_threshold": None, "connect_timeout": 10,
                                       "sslmode": s.database_sslmode})


@contextmanager
def tenant_session(user_id, org_id):
    db = engine()
    try:
        with Session(db) as session, session.begin():
            session.execute(text('SET LOCAL ROLE cisguard_api'))
            session.execute(text("SELECT set_config('app.user_id', :u, true), set_config('app.org_id', :o, true)"),
                            {"u": str(user_id), "o": str(org_id)})
            yield session
    finally:
        db.dispose()
