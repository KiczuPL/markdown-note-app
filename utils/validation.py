import re
from math import log2

import bleach
import markdown

from app import NOTE_MAX_LENGTH

MINIMAL_PASSWORD_ENTROPY = 3.4


def verify_note_content(note: str):
    is_valid = True
    messages = []

    if not note or note.isspace():
        messages.append("Note is empty")

    md = markdown.markdown(bleach.clean(note))

    if len(md) > NOTE_MAX_LENGTH:
        is_valid = False
        messages.append(f"Note is too long, max length: {NOTE_MAX_LENGTH}")
        return is_valid, messages

    regex = '<img[^>]*src="([^"]+)"[^>]*>'
    res = re.findall(regex, md)
    for image_link in res:
        print(image_link)
        if not validate_image_link(image_link):
            is_valid = False
            messages.append(f"Image link: [{image_link}] is invalid")
            break

    return is_valid, messages


def validate_image_link(link: str):
    if not re.search(r"127.0.0.1|localhost", link):
        return False
    if not re.search(r"^https:\\", link):
        return False
    if not re.search(r".(gif|jpg|jpeg|png)", link):
        return False
    return True


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
    # regex = r"^[a-zA-Z0-9@$!%*?&- ]{1,25}$"
    # match = re.compile(regex)
    # res = re.search(match, title)
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
