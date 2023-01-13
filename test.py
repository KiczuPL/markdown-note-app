import bleach
import markdown
t = "a"
cleaned = bleach.clean(t)
md = markdown.markdown(cleaned)

print(str.)
