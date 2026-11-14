from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .api.users import router as users_router

app = FastAPI(title="Vulnerable API")

# Insecure CORS wildcard with credentials
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(users_router)

