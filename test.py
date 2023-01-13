import datetime
from passlib.hash import bcrypt
import time
import bleach
import markdown
from math import log2
t = "aaaaaaaaaaaaaaaaaaaaaa5$"
cleaned = bleach.clean(t)
md = markdown.markdown(cleaned)


print(datetime.datetime.now())
print(None > datetime.datetime.now())
