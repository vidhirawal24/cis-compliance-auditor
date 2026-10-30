from alembic import context
from cisguard_api.database import engine
from cisguard_api.db_models import Base

db = engine(migration=True)
with db.connect() as connection:
    context.configure(connection=connection, target_metadata=Base.metadata, include_schemas=True,
                      version_table='cisguard_alembic_version')
    with context.begin_transaction():
        context.run_migrations()
db.dispose()
