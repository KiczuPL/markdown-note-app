import bleach
import markdown
from math import log2
t = "aaaaaaaaaaaaaaaaaaaaaa5$"
cleaned = bleach.clean(t)
md = markdown.markdown(cleaned)


def password_entropy(password: str):
    entropy = 0.0
    hist = {}
    for c in password:
        if c in hist:
            hist[c] += 1
        else:
            hist[c] = 1

    size = 0
    for c in hist:
        size = size + hist[c]

    print(hist)
    for i in hist:
        prob = password.count(i)/size
        if prob > 0.0:
            entropy += prob * log2(prob)

    return -entropy


print(password_entropy(t))
