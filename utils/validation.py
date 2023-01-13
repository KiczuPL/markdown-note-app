import re


def verify_password(password: str):
    regex = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$"
    match = re.compile(regex)
    res = re.search(match, password)
    if not res:
        return False
    return True


def verify_username(username: str):
    regex = r"^[a-zA-Z0-9]{5,20}$"
    match = re.compile(regex)
    res = re.search(match, username)
    if not res:
        return False
    return True
