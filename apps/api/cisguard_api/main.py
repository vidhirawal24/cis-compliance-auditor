from uuid import UUID, uuid4
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from sqlalchemy.exc import SQLAlchemyError
from .database import tenant_session
from .security_routes import router as security_router
from .job_routes import router as job_router
from .policy_routes import router as policy_router
from .report_routes import report_router
from .graph_routes import graph_router
from .plan_routes import plan_router
from .change_routes import change_router
from .proof_routes import proof_router

app = FastAPI(title="CISGuard 360", version="0.9.0")
app.include_router(security_router)
app.include_router(job_router)
app.include_router(policy_router)
app.include_router(report_router)
app.include_router(graph_router)
app.include_router(plan_router)
app.include_router(change_router)
app.include_router(proof_router)


@app.middleware("http")
async def request_identity(request: Request, call_next):
    request.state.request_id = str(uuid4())
    response = await call_next(request)
    response.headers["X-Request-ID"] = request.state.request_id
    return response


def error(request, status, code, message, retryable=False):
    return JSONResponse(
        status_code=status,
        content=dict(code=code, message=message, request_id=request.state.request_id, retryable=retryable),
    )


@app.exception_handler(HTTPException)
async def http_error(request, exc):
    record_denial(request, exc.status_code)
    code = {
        401: "UNAUTHENTICATED",
        403: "FORBIDDEN",
        409: "CONFLICT",
        422: "VALIDATION_ERROR",
        429: "RATE_LIMITED",
        503: "DEPENDENCY_UNAVAILABLE",
    }.get(exc.status_code, "NOT_FOUND")
    if exc.detail == "MFA_REQUIRED":
        code = "MFA_REQUIRED"
    response = error(request, exc.status_code, code, str(exc.detail), exc.status_code in (429, 503))
    if exc.status_code == 429:
        response.headers["Retry-After"] = "60"
    return response


@app.exception_handler(RequestValidationError)
async def validation_error(request, exc):
    return error(request, 422, "VALIDATION_ERROR", "Invalid request")


@app.exception_handler(SQLAlchemyError)
async def database_error(request, exc):
    if getattr(getattr(exc, "orig", None), "sqlstate", None) == "42501":
        record_denial(request, 403)
        return error(request, 403, "FORBIDDEN", "Operation denied")
    return error(request, 503, "DEPENDENCY_UNAVAILABLE", "Database unavailable", True)


@app.get("/health/live")
def live():
    return {"status": "ok", "phase": "jobs"}


def record_denial(request, status):
    if status not in (401, 403, 429, 503):
        return
    from sqlalchemy import text
    import logging

    reasons = {
        401: "AUTH_DENIED",
        403: "PERMISSION_DENIED",
        429: "RATE_LIMITED",
        503: "DEPENDENCY_UNAVAILABLE",
    }
    try:
        with tenant_session(UUID(int=0), UUID(int=0)) as db:
            db.execute(
                text("SELECT cisguard.log_denial(:r,:w)"),
                {"r": request.state.request_id, "w": reasons[status]},
            )
    except SQLAlchemyError:
        logging.getLogger("cisguard.security").warning(
            "Denied request audit persistence unavailable: %s", request.state.request_id
        )
