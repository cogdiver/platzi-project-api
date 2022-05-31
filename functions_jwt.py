from jwt import encode, decode, exceptions
from fastapi.responses import JSONResponse
from datetime import datetime, timedelta
from os import getenv
from pymongo import MongoClient
from passlib.context import CryptContext


host = getenv("DATABASE_HOST")
port = getenv("DATABASE_PORT")
user = getenv("DATABASE_USER")
password = getenv("DATABASE_PASSWORD")
client = MongoClient(f'mongodb://{user}:{password}@{host}:{port}')
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
db = client.platzi


def get_user(email: str, fields=[]):
    return db.users.find_one({"email": email}, {f:1 for f in fields})


def create_user(user):
    hashed_password = get_password_hash(user['password'])
    del user['password']

    id = db.users.insert_one({
        **user,
        "image": f"https://www.tinygraphs.com/isogrids/{user['name']}",
        "hashed_password": hashed_password,
        "courses": [],
        "routes": []
    }).inserted_id

    return write_token({
        "_id": str(id),
        "email": user['email'],
        "hashed_password": hashed_password
    })


def expire_date(days: int):
    date = datetime.now()
    return date + timedelta(days)


def write_token(data: dict):
    token = encode(
        payload={**data, "exp": expire_date(2)},
        key=getenv("JWT"),
        algorithm="HS256"
    )
    return token


def validate_token(token, output=False):
    try:
        token_ = decode(token, key=getenv("JWT"), algorithms=["HS256"])
        if output:
            return token_

    except exceptions.DecodeError:
        return JSONResponse(
            content={"message": "Invalid token"},
            status_code=401
        )

    except exceptions.ExpiredSignatureError:
        return JSONResponse(
            content={"message": "Token Expired"},
            status_code=401
        )


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def authenticate_user(email: str, password: str):
    user = get_user(email, fields=["email", "hashed_password"])

    if not user:
        return {"error": "User not found"}

    if not verify_password(password, user['hashed_password']):
        return {"error": "Invalid password"}

    return {**user, '_id': str(user['_id'])}
