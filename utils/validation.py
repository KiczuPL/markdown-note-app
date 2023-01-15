import re
from math import log2

MINIMAL_PASSWORD_ENTROPY = 3.4


def verify_note_content(note: str):
    is_valid = True
    messages = []


def verify_password(password: str):
    regex = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{10,128}$"
    match = re.compile(regex)
    res = re.search(match, password)
    if not res:
        return False
    return True


def verify_username(username: str):
    regex = r"^[a-zA-Z0-9]{3,20}$"
    match = re.compile(regex)
    res = re.search(match, username)
    if not res:
        return False
    return True


def verify_note_title(title: str):
    #regex = r"^[a-zA-Z0-9@$!%*?&- ]{1,25}$"
    #match = re.compile(regex)
    #res = re.search(match, title)
    if title is None or title.isspace() or len(title) < 1 or len(title) > 25:
        return False
    return True


def verify_password_strength(password: str):
    entropy = 0.0
    hist = {}
    for c in password:
        if c in hist:
            hist[c] += 1
        else:
            hist[c] = 1

    size = len(password)

    for i in hist:
        prob = password.count(i)/size
        if prob > 0.0:
            entropy += prob * log2(prob)

    return -entropy < MINIMAL_PASSWORD_ENTROPY, -entropy
