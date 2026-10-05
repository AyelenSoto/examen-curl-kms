import boto3, json, base64
from cryptography.fernet import Fernet

kms = boto3.client("kms", region_name="us-east-1")

key = kms.create_key()["KeyMetadata"]["KeyId"]
data = kms.generate_data_key(KeyId=key, KeySpec="AES_256")

fkey = base64.urlsafe_b64encode(data["Plaintext"])
msg = Fernet(fkey).encrypt(b"Mensaje secreto")

sobre = {
    "mensaje": base64.b64encode(msg).decode(),
    "key": base64.b64encode(data["CiphertextBlob"]).decode()
}

with open("sobre.json", "w") as f:
    json.dump(sobre, f)

def descifrar():
    key = kms.decrypt(CiphertextBlob=base64.b64decode(sobre["key"]))["Plaintext"]
    mensaje = Fernet(base64.urlsafe_b64encode(key)).decrypt(
        base64.b64decode(sobre["mensaje"])
    )
    print("Mensaje:", mensaje.decode())
    print("Key:", key.hex())

descifrar()
kms.schedule_key_deletion(KeyId=key, PendingWindowInDays=7)