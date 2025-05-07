from fastapi import FastAPI
from rest.system_endpoint import router as SystemEndpoint
from rest.auth_endpoint import router as AuthEndpoint


app = FastAPI(
    title="nerd",
    description="nerd",
    version="0.0.1",
)

app.include_router(SystemEndpoint)
app.include_router(AuthEndpoint)
