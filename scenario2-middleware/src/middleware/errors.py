from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

PROBLEM_JSON_MEDIA_TYPE = "application/problem+json"

STATUS_TITLES: Dict[int, str] = {
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    422: "Unprocessable Entity",
    429: "Too Many Requests",
    500: "Internal Server Error",
    502: "Bad Gateway",
    503: "Service Unavailable",
    504: "Gateway Timeout",
}


def build_problem_response(
    status_code: int,
    detail: Optional[str] = None,
    title: Optional[str] = None,
    instance: Optional[str] = None,
    problem_type: Optional[str] = None,
    headers: Optional[Dict[str, str]] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> JSONResponse:
    """
    Constructs an RFC 7807 problem details JSONResponse with media type 'application/problem+json'.
    """
    effective_title = title or STATUS_TITLES.get(status_code, "HTTP Error")
    effective_type = problem_type or "about:blank"

    payload: Dict[str, Any] = {
        "type": effective_type,
        "title": effective_title,
        "status": status_code,
        "detail": detail or effective_title,
    }
    if instance:
        payload["instance"] = instance

    if extra:
        payload.update(extra)

    response_headers = dict(headers or {})
    return JSONResponse(
        status_code=status_code,
        content=payload,
        media_type=PROBLEM_JSON_MEDIA_TYPE,
        headers=response_headers,
    )


def register_problem_handlers(app: FastAPI) -> None:
    """
    Registers global RFC 7807 exception handlers on the FastAPI application.
    """

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
        instance = request.url.path
        headers = dict(exc.headers or {})
        detail_msg = exc.detail if isinstance(exc.detail, str) else str(exc.detail)

        # Ensure 503 has Retry-After if not already set
        if exc.status_code == status.HTTP_503_SERVICE_UNAVAILABLE and "Retry-After" not in headers:
            headers["Retry-After"] = "1"

        return build_problem_response(
            status_code=exc.status_code,
            detail=detail_msg,
            instance=instance,
            headers=headers,
        )

    @app.exception_handler(StarletteHTTPException)
    async def starlette_http_exception_handler(
        request: Request, exc: StarletteHTTPException
    ) -> JSONResponse:
        instance = request.url.path
        headers = dict(exc.headers or {})
        detail_msg = exc.detail if isinstance(exc.detail, str) else str(exc.detail)
        if exc.status_code == status.HTTP_503_SERVICE_UNAVAILABLE and "Retry-After" not in headers:
            headers["Retry-After"] = "1"

        return build_problem_response(
            status_code=exc.status_code,
            detail=detail_msg,
            instance=instance,
            headers=headers,
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        instance = request.url.path
        raw_errors = exc.errors()
        # Create a helpful human-readable detail string containing field names and messages
        messages: List[str] = []
        for err in raw_errors:
            loc = " -> ".join(str(loc_item) for loc_item in err.get("loc", []))
            msg = err.get("msg", "Validation error")
            messages.append(f"{loc}: {msg}" if loc else msg)
        detail = "; ".join(messages) if messages else "Invalid request payload."

        return build_problem_response(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            title="Unprocessable Entity",
            detail=detail,
            instance=instance,
            extra={"errors": jsonable_encoder(raw_errors)},
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        instance = request.url.path
        return build_problem_response(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            title="Internal Server Error",
            detail=f"An unexpected internal error occurred: {type(exc).__name__}",
            instance=instance,
        )
