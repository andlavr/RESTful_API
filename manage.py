import uuid
import uvicorn

from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.security import OAuth2PasswordBearer

from passlib.context import CryptContext
from verification import create_jwt_token



app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def generate_id():
    """
    Generates user id

    :return: id_
    """
    id_ = str(uuid.uuid4())
    return id_


data_list = []


@app.post("/register")
def register_user(email: str, password: str, id_: str = Depends(generate_id)):
    """
    Registration of new user

    :param email: email address of user
    :param password: password to email
    :param id_: user id
    :return: dict with user details
    """

    hashed_password = pwd_context.hash(password)
    current_dict = {"id": id_, "email": email, "password": password, "hashed_password": hashed_password}
    data_list.append(current_dict)
    return {"id": id_, "email": email}


def get_user_by_email(email: str):
    """
    Get user by email

    :param email: user's email address
    :return: user
    """
    for user in data_list:
        if email == user["email"]:
            return user


def get_refresh_token():
    """
    Get refresh token

    :return: refresh token
    """
    ref = str(uuid.uuid4())
    return ref


@app.post("/login")
def authentification_user(email: str, password: str):
    """
    Users authentication with email and password

    :param email: email of user
    :param password: password for email
    :return: dict with user details
    """
    user = get_user_by_email(email)
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect email or password")

    is_password_correct = pwd_context.verify(password, user["hashed_password"])
    refresh_token = get_refresh_token()

    print(data_list)
    for user in data_list:
        if user["email"] == email:
            user["refresh_token"] = refresh_token
            user["access_token"] = create_jwt_token({'sub': user["email"]})

    print(user)
    print(data_list)
    if not is_password_correct:
        raise HTTPException(status_code=400, detail="Incorrect email or password")

    jwt_token = create_jwt_token({'sub': user["email"]})
    return {"access_token": jwt_token, "refresh_token": refresh_token}


@app.post("/refresh")
def refresh_token(refresh_token: str, email: str):
    """
    Refresh token of user

    :param refresh_token: current refresh token
    :param email: user's email
    :return: dict with refresh token and access token
    """
    user = get_user_by_email(email)
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    print(refresh_token, user["refresh_token"])
    if user["email"] == email:
        if user["refresh_token"] != refresh_token:
            raise HTTPException(status_code=400, detail="Incorrect refresh token")

        refresh_token = get_refresh_token()
        user["refresh_token"] = refresh_token

        access_token = create_jwt_token({'sub': user["email"]})
        user["access_token"] = access_token

        return {"access_token": access_token, "refresh_token": refresh_token}


@app.post("/logout")
def logout_user(refresh_token: str, email: str):
    """
    Logout user

    :param refresh_token: current refresh token
    :param email: email of user
    :return: dict with message
    """
    user = get_user_by_email(email)
    if user["refresh_token"] == refresh_token:
        user.pop("refresh_token")
        user.pop("access_token")

        return {"success": "User logged out."}


@app.get("/me")
def get_current_user(access_token: str | None = Header(default=None)):
    """
    Get user data

    :param access_token: current access token
    :return: user's data
    """
    for user in data_list:
        if user["access_token"] == access_token:
            user["username"] = ''
            return user


@app.put("/me/username")
def put_current_user(username: str, email: str, access_token: str | None = Header(default=None)):
    """
    Username update

    :param username: the name of user
    :param email: email of user
    :param access_token: current access token
    :return: updated user's data
    """
    if email == email and access_token == access_token:
        user = get_user_by_email(email)
        user["username"] = username
        return user


@app.put("/me/password")
def put_current_user_password(username: str, email: str, password: str,
                              access_token: str | None = Header(default=None)):
    """
    An additional method not included in the task.

    Method change the password of user

    :param username: the name of user
    :param email:email of user
    :param password: current password of user
    :param access_token:current access token
    :return:updated user's data
    """
    if username == username and access_token == access_token:
        user = get_user_by_email(email)
        user["password"] = password
        hashed_password = pwd_context.hash(password)
        return user


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8001)
