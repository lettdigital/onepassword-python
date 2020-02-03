from onepassword import OnePassword

secret = {"password": "<YOUR-PASSWORD-HERE>",
          "username": "<YOUR-USERNAME-HERE>",
          "signin_address": "<YOUR-1PASSWORD-ORGNIZATION-ADDRESS>",
          "secret_key": "<YOUR-1PASSWORD-SECRET-KEY>"}
op = OnePassword(secret=secret)

documents = op.list("documents")
pem_keys = (doc for doc in documents if doc["overview"]["title"].endswith("pem"))
first_key = next(pem_keys)
key_contents = op.get("document", first_key["uuid"])
print(key_contents)
