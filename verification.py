import jwt
from datetime import datetime, timedelta

SECRET_KEY = '111'
ALGORITHM = 'HS256'
EXPIRATION_TIME = timedelta(days=30)


def create_jwt_token(data: dict) -> str:
    """
    Create jwt token for user
    :param data: dict with user name
    :return: token
    """
    print(data, type(data))
    expiration = datetime.utcnow() + EXPIRATION_TIME
    data.update({'exp': expiration})
    token = jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

    return token

def verify_jwt_token(token: str) -> dict:
    """
    Verify jwt token

    :param token: token
    :return: None
    """
    try:
        decoded_data = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

        return decoded_data

    except jwt.PyJWTError:
        return None