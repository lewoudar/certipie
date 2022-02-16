from fastapi import FastAPI
from fastapi.middleware import Middleware
from fastapi.middleware.gzip import GZipMiddleware

from .cert import router

app = FastAPI(
    title='certificate api',
    description='Utilities to create certificate CSR and auto-certificate for testing purpose',
    redoc_url=None,
    middleware=[Middleware(GZipMiddleware, minimum_size=1000)]
)
app.include_router(router, prefix='/certs')
