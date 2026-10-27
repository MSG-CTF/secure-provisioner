"""Runtime-only HTTP API. Nginx remains the participant traffic proxy."""

from contextlib import asynccontextmanager
import json
import os
import secrets
import subprocess
from typing import Annotated, Literal

from fastapi import FastAPI, Path, Request, Response, Security
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator, model_validator
from starlette.exceptions import HTTPException as StarletteHTTPException

from gateway.controller import COMMAND_ENV, INSTANCE_PATTERN, public_ip


CONTROLLER = [
    "/usr/bin/sudo", "-n", "/usr/bin/python3", "-I",
    "/opt/msgctf-gateway/gateway/controller.py",
]
bearer = HTTPBearer(
    auto_error=False, scheme_name="RuntimeBearer",
    description="The same fixed RUNTIME_API_TOKEN used by the Broker.",
)


class GatewayError(Exception):
    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status, self.code = status, code


class ApiSchema(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RouteRequest(ApiSchema):
    target_ip: str = Field(
        strict=True, min_length=3, max_length=45,
        description="Public IPv4/IPv6 of the problem VM, supplied by the trusted Runtime.",
    )
    target_port: int = Field(
        strict=True, ge=1, le=65535,
        description="Plaintext backend TCP port reachable from the Gateway.",
    )
    protocol: Literal["http", "tcp"] = Field(
        description="http keeps HTTPS/443; new tcp routes may receive a public plaintext port when the Gateway pool is enabled.",
    )

    @field_validator("target_ip")
    @classmethod
    def require_public_ip(cls, value: str) -> str:
        return public_ip(value)


class RouteResponse(ApiSchema):
    instance_id: str
    hostname: str
    port: int = Field(strict=True, ge=1, le=65535)
    tls: bool = Field(strict=True)
    protocol: Literal["http", "tcp"]
    url: str | None
    created_at: AwareDatetime

    @model_validator(mode="after")
    def consistent_transport(self):
        if self.protocol == "http":
            if self.port != 443 or not self.tls or self.url != f"https://{self.hostname}":
                raise ValueError("HTTP routes require their existing HTTPS URL and port 443.")
        elif self.url is not None or (self.tls and self.port != 443) or (not self.tls and self.port < 1024):
            raise ValueError("Invalid TCP transport metadata.")
        return self


class ErrorDetail(ApiSchema):
    code: str
    message: str


class ErrorResponse(ApiSchema):
    error: ErrorDetail


def configured_token() -> str:
    token = os.getenv("RUNTIME_API_TOKEN", "")
    if len(token) < 32 or token != token.strip():
        raise GatewayError(503, "RUNTIME_AUTH_NOT_CONFIGURED", "Runtime authentication is not configured.")
    return token


def require_runtime(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Security(bearer)],
) -> None:
    token = configured_token()
    if credentials is None or not secrets.compare_digest(
        credentials.credentials.encode("utf-8"), token.encode("utf-8"),
    ):
        raise GatewayError(401, "INVALID_RUNTIME_TOKEN", "A valid Runtime Bearer token is required.")


def controller(request: dict) -> tuple[int, dict | None]:
    try:
        result = subprocess.run(
            CONTROLLER, input=json.dumps(request), capture_output=True,
            text=True, timeout=60, check=False, env=COMMAND_ENV,
        )
        if result.returncode != 0:
            raise ValueError("The controller process failed.")
        reply = json.loads(result.stdout)
        status, body = reply["status"], reply["body"]
        if status not in {200, 201, 204, 400, 404, 409, 422, 502, 503}:
            raise ValueError("Invalid controller status.")
        if status >= 400:
            error = ErrorResponse.model_validate(body).error
            raise GatewayError(status, error.code, error.message)
        return status, body
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError) as error:
        raise GatewayError(503, "CONTROLLER_UNAVAILABLE", "The route controller is unavailable.") from error


@asynccontextmanager
async def lifespan(_: FastAPI):
    configured_token()
    controller({"operation": "reconcile"})
    yield


InstanceId = Annotated[str, Path(
    pattern=INSTANCE_PATTERN, min_length=1, max_length=255,
    description="Unique per-team deployment ID. Retry with the same ID and body; do not reuse deleted IDs.",
)]
ERRORS = {status: {"model": ErrorResponse} for status in (400, 401, 404, 409, 422, 500, 502, 503)}


def create_app() -> FastAPI:
    app = FastAPI(
        title="MSGCTF Gateway Management API", version="1.1.0",
        docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan,
        servers=[{"url": "https://gate.msgctf.kr"}],
        dependencies=[Security(require_runtime)],
    )

    @app.exception_handler(GatewayError)
    async def gateway_error(_: Request, error: GatewayError) -> JSONResponse:
        return JSONResponse(
            status_code=error.status,
            headers={"WWW-Authenticate": "Bearer"} if error.status == 401 else None,
            content={"error": {"code": error.code, "message": str(error)}},
        )

    @app.exception_handler(RequestValidationError)
    async def invalid_request(_: Request, error: RequestValidationError) -> JSONResponse:
        invalid_json = any(item["type"] == "json_invalid" for item in error.errors())
        return JSONResponse(
            status_code=400 if invalid_json else 422,
            content={"error": {
                "code": "INVALID_JSON" if invalid_json else "VALIDATION_ERROR",
                "message": "The request JSON or parameters are invalid.",
            }},
        )

    @app.exception_handler(StarletteHTTPException)
    async def http_error(_: Request, error: StarletteHTTPException) -> JSONResponse:
        return JSONResponse(
            status_code=error.status_code,
            content={"error": {
                "code": "NOT_FOUND" if error.status_code == 404 else "HTTP_ERROR",
                "message": "The requested HTTP operation is unavailable.",
            }},
        )

    @app.exception_handler(Exception)
    async def unexpected_error(_: Request, error: Exception) -> JSONResponse:
        del error
        return JSONResponse(
            status_code=500,
            content={"error": {"code": "INTERNAL_ERROR", "message": "The Gateway could not process the request."}},
        )

    @app.put(
        "/v1/routes/{instance_id}", response_model=RouteResponse, responses={
            **ERRORS, 201: {"model": RouteResponse, "description": "New route registered."},
        }, summary="Register an instance route; retry with the same ID and body",
    )
    def put_route(instance_id: InstanceId, body: RouteRequest, response: Response) -> RouteResponse:
        status, result = controller({"operation": "put", "instance_id": instance_id, **body.model_dump()})
        response.status_code = status
        return RouteResponse.model_validate(result)

    @app.get(
        "/v1/routes/{instance_id}", response_model=RouteResponse,
        responses=ERRORS, summary="Get the registered public connection address",
    )
    def get_route(instance_id: InstanceId) -> RouteResponse:
        _, result = controller({"operation": "get", "instance_id": instance_id})
        return RouteResponse.model_validate(result)

    @app.delete(
        "/v1/routes/{instance_id}", status_code=204, response_class=Response,
        responses=ERRORS, summary="Remove an instance route; safe to retry",
    )
    def delete_route(instance_id: InstanceId) -> Response:
        controller({"operation": "delete", "instance_id": instance_id})
        return Response(status_code=204)

    @app.get("/v1/openapi.json", include_in_schema=False)
    def openapi() -> dict:
        return app.openapi()

    return app


app = create_app()
