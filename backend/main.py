from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from backend.database import save_password, get_password
from backend.password_checker import check_password_strength, generate_password
from backend.pwned_checker import check_pwned_password
from backend.security import encrypt_password, decrypt_password

app = FastAPI()


# Define request models for JSON input
class PasswordRequest(BaseModel):
    user_id: str
    password: str


class EncryptRequest(BaseModel):
    password: str


class DecryptRequest(BaseModel):
    encrypted_password: str


class PasswordCheckRequest(BaseModel):
    password: str  # No user_id needed


@app.get("/")
def home():
    return {"message": "Password Analyzer API is running!"}


@app.post("/encrypt/")
def encrypt(data: EncryptRequest):
    """Encrypts a given password."""
    try:
        encrypted = encrypt_password(data.password)
        return {"encrypted_password": encrypted}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/decrypt/")
def decrypt(data: DecryptRequest):
    """Decrypts an encrypted password."""
    try:
        decrypted = decrypt_password(data.encrypted_password)
        return {"decrypted_password": decrypted}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/save_password/")
def save_user_password(data: PasswordRequest):
    """Encrypts and saves a password for a user."""
    try:
        save_password(data.user_id, data.password)
        return {"message": "Password saved successfully!"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/get_password/")
def retrieve_user_password(user_id: str):
    """Retrieves a decrypted password for a user."""
    try:
        password = get_password(user_id)
        return {"password": password}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/generate_password/")
def generate_random_password(length: int = 16, exclude_special: bool = False):
    """Generates a strong random password."""
    try:
        password = generate_password(length, exclude_special)
        return {"password": password}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/check_password/")
def analyze_password(data: PasswordCheckRequest):
    """
    Endpoint to check password strength.
    """
    try:
        strength_result = check_password_strength(data.password)
        pwned_result = check_pwned_password(data.password)

        return {
            "password_strength": strength_result,
            "pwned_status": pwned_result
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
