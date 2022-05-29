from fastapi import FastAPI
from dotenv import load_dotenv
from routes.auth import auth_routes

load_dotenv()

app = FastAPI()
app.include_router(auth_routes)


@app.get('/')
def home():
    return 'Ok'