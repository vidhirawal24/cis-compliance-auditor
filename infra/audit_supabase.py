import json
import httpx
from sqlalchemy import text
from cisguard_api.database import engine
from cisguard_api.settings import get_settings

s = get_settings()

print("=== 1. SUPABASE POSTGRESQL AUDIT ===")
db = engine(migration=True)
with db.connect() as conn:
    version = conn.execute(text("SELECT version()")).scalar()
    print("PostgreSQL version:", " ".join(version.split()[0:2]))
    
    # Tables in cisguard schema
    tables = conn.execute(text("""
        SELECT table_name 
        FROM information_schema.tables 
        WHERE table_schema = 'cisguard'
        ORDER BY table_name
    """)).scalars().all()
    print(f"Tables in cisguard schema ({len(tables)}):", tables)
    
    # RLS status on all cisguard tables
    rls_status = conn.execute(text("""
        SELECT relname, relrowsecurity, relforcerowsecurity 
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'cisguard' AND c.relkind = 'r'
        ORDER BY relname
    """)).fetchall()
    print("RLS status on tables:")
    all_rls = True
    for r in rls_status:
        print(f"  - {r[0]}: rls_enabled={r[1]}, force_rls={r[2]}")
        if not r[1]:
            all_rls = False
    print("All tables RLS enabled:", all_rls)
    
    # Alembic current revision in database
    alembic_rev = conn.execute(text("SELECT version_num FROM cisguard_alembic_version")).scalar()
    print("Alembic migration version in DB:", alembic_rev)
    
    # Policies in cisguard schema
    policies = conn.execute(text("""
        SELECT tablename, policyname, roles, cmd 
        FROM pg_policies 
        WHERE schemaname = 'cisguard'
        ORDER BY tablename, policyname
    """)).fetchall()
    print(f"Active RLS policies ({len(policies)}):")
    for p in policies:
        print(f"  - {p[0]}.{p[1]} ({p[3]}) TO {p[2]}")

print("\n=== 2. SUPABASE AUTH & JWKS AUDIT ===")
supabase_url = s.supabase_url
jwks_url = f"{supabase_url}/auth/v1/.well-known/jwks.json"
with httpx.Client(timeout=10) as client:
    try:
        r_jwks = client.get(jwks_url)
        print("JWKS endpoint HTTP status:", r_jwks.status_code)
        if r_jwks.status_code == 200:
            keys = r_jwks.json().get("keys", [])
            print(f"JWKS public keys available: {len(keys)}")
    except Exception as e:
        print("JWKS fetch error:", e)

print("\n=== 3. SUPABASE STORAGE AUDIT ===")
storage_url = f"{supabase_url}/storage/v1/bucket"
anon_key = s.supabase_anon_key.get_secret_value()
headers = {"apikey": anon_key, "Authorization": f"Bearer {anon_key}"}
with httpx.Client(timeout=10) as client:
    try:
        r_stor = client.get(storage_url, headers=headers)
        print("Storage bucket list status (anon key):", r_stor.status_code)
        if r_stor.status_code == 200:
            buckets = r_stor.json()
            print("Existing Storage buckets:", [b.get("id") for b in buckets])
        else:
            print("Storage response status:", r_stor.status_code)
    except Exception as e:
        print("Storage check error:", e)

print("\n=== 4. SUPABASE REALTIME AUDIT ===")
realtime_url = f"{supabase_url}/realtime/v1"
with httpx.Client(timeout=10) as client:
    try:
        r_rt = client.get(f"{realtime_url}/health?apikey={anon_key}")
        print("Realtime health status with apikey query param:", r_rt.status_code, r_rt.text.strip())
    except Exception as e:
        print("Realtime HTTP check error:", e)

