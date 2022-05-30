from logging import getLogger
from typing import Union

from cryptography.exceptions import UnsupportedAlgorithm
from fastapi import FastAPI, Request
from fastapi.middleware import Middleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse

from .cert import router

logger = getLogger(__name__)


async def cert_exception(request: Request, exc: Union[TypeError, ValueError, UnsupportedAlgorithm]) -> JSONResponse:
    logger.error('operation on route %s %s failed', request.method, str(request.url))
    # TODO: understand why the relevant test blocks on pytest on the following line
    # logger.error('request form passed: %s', await request.form())
    return JSONResponse(status_code=422, content={'detail': str(exc)})


exception_handlers = {TypeError: cert_exception, ValueError: cert_exception, UnsupportedAlgorithm: cert_exception}

app = FastAPI(
    title='certificate api',
    version='0.2.0',
    description='Utilities to create certificate signing request and self-signed certificate for testing purpose',
    redoc_url=None,
    docs_url='/',
    middleware=[Middleware(GZipMiddleware, minimum_size=1000)],
    exception_handlers=exception_handlers,
)
app.include_router(router, prefix='/certs', tags=['certificate'])
