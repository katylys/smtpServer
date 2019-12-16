import smtplib

smtp_server = "127.0.0.1"
port = 589  # For starttls
sender_email = "user3@memdomain.com"
password = "1234"  # input("Type your password and press enter: ")

# Try to log in to server and send email
#try:
#     server = smtplib.SMTP(smtp_server, port)
#     # server.login(sender_email, password)
receiver = ["user2@memdomain.com", "user1@memdomain.com"]
#     message = """\
# To: %s
# Subject: server test
#
# aloha
#     """ % receiver[0]
try:
    server = smtplib.SMTP('127.0.0.1', 587)
    server.ehlo()
    server.login(sender_email, '1234')
    print("ok")
    data = """\\
To: %s
Subject: server test

aloha""" % (receiver[0])
    server.sendmail("user3@memdomain.com", ["user1@memdomain.com", "user2@memdomain.com"], data)
    print("ok")
except Exception as e:
    print(e)
