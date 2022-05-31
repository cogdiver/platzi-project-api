from fastapi import APIRouter, Header
from pydantic import BaseModel, EmailStr
from fastapi.responses import JSONResponse
from functions_jwt import create_user, get_user, validate_token, write_token, authenticate_user


auth_routes = APIRouter()

class User(BaseModel):
    email: EmailStr
    password: str

class UserSignUp(User):
    name: str


@auth_routes.post('/signin')
def signin(user: User):
    user_content = authenticate_user(**user.dict())

    if not user_content.get('error'):
        return {
            "token": write_token({**user_content})
        }

    else:
        return JSONResponse(
            content={"error": user_content.get('error')},
            status_code=404
        )


@auth_routes.post('/signup')
def signup(user: UserSignUp):
    user_content = get_user(user.email, fields=['_id'])

    if not user_content:
        return {
            "token": create_user(user.dict())
        }

    else:
        return JSONResponse(
            content={"error": "User already exists"},
            status_code=403
        )


@auth_routes.post('/verify/token')
def verity_token(Authorization: str = Header(None)):
    token = Authorization.split(' ')[1]
    
    return validate_token(token, output=True)
