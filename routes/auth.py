from fastapi import APIRouter
from pydantic import BaseModel, EmailStr
from fastapi.responses import JSONResponse
from functions_jwt import write_token, authenticate_user


auth_routes = APIRouter()

class User(BaseModel):
    email: EmailStr
    password: str


@auth_routes.post('/login')
def login(user: User):
    user_content = authenticate_user(**user.dict())
    if not user_content.get('error'):
        return {
            "user_content": user_content,
            "token": write_token(user.dict())
        }
    else:
        return JSONResponse(
            content={"message": user_content.get('error')},
            status_code=404
        )
