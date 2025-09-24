from Crypto.PublicKey import RSA
key = RSA.generate(2048)
with open("server_private.pem", "wb") as f: f.write(key.export_key())
with open("server_public.pem", "wb") as f: f.write(key.publickey().export_key())
print("Successfully generated server_private.pem and server_public.pem")
