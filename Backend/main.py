from fastapi import FastAPI, Depends, HTTPException, status
from .database import engine, Base, get_db
from sqlalchemy.orm import Session
from .models import User
from .schema import UserCreated
from pwdlib import PasswordHash
from datetime import datetime, timedelta, timezone
import jwt
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()
Base.metadata.create_all(bind=engine)

origins = [
    "http://localhost:8080",
    "http://localhost:3000"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# @app.get("/api", response_model=List[UserResponse])
# def read_users(db: Session = Depends(get_db)): #เมื่อมี Request db (type=Session) ให้เรียกใช้ get_db แล้วเก็บไว้ใน db
#     db_items = db.query(User).all()
#     return [ UserResponse(id=str(user.id),username=user.username) for user in db_items]

# @app.get("/api/{user_id}", response_model=UserResponse)
# def read_user(user_id: str, q: Union[str, None] = None, db: Session = Depends(get_db)):
#     user = db.query(User).filter(User.id == user_id).first()
#     if not user:
#         raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Invalid ID.")
#     if user:
#         user.id = str(user.id)
#     return user

password_hash = PasswordHash.recommended() #Hashoassword จากการสมัครของ User
def get_password_hash(password):
    """Get hashed password"""
    return password_hash.hash(password)

@app.post("/api/register")
def create_user(user_input: UserCreated, db: Session = Depends(get_db)):
    """API for register an acount"""
    user = db.query(User).filter(User.username == user_input.username).first()
    if user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already exists.")
    user_input.password = get_password_hash(user_input.password)
    user_input = User(**user_input.model_dump())
    db.add(user_input)
    db.commit()
    return { "message" : "Success" }

def verify_password(plain_password, hashedpassword): # ใช้ในการเช็คว่ารหัสที่ user ป้อนมาตรงกับที่ hash ไว้ในระบบไหม
    """Check plainpassword and hashedpassword (Use for Login System)"""
    return password_hash.verify(plain_password, hashedpassword)

def get_user(db, username : str):
    """Check user in Database or not"""
    user = db.query(User).filter(User.username == username).first()
    if user:
        return user

def authenticate_user(db, username: str, password: str): # เช็คดูว่ามี user นี้จริงๆไหมแล้วรหัสตรงกับที่ hash ไหมถ้ามี return user ออกไป
    """Check User Login system correct or not"""
    user = get_user(db, username)
    if not user:
        return False
    if not verify_password(password, user.password):
        return False
    return user

SECRET_KEY = "f3e0d5c8c7f8467c9d2b4a8e34c6a1e0b7f9d9a5a2f442e7a0c2e5d3b8f7c4e9"
ACCESS_TOKEN_EXPIRE_MINUTES = 1440
ALGORITHM = "HS256"
def create_access_token(data: dict, expires_delta: timedelta | None = None):
    """Create Token After Login Success"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=1440)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

@app.post("/api/login")
async def login_for_access_token(user_input: UserCreated, db: Session = Depends(get_db)):
    """API For Login System"""
    user = authenticate_user(db, user_input.username, user_input.password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password", headers={"WWW-Authenticate" : "Bearer"})
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.username}, expires_delta=access_token_expires)
    response = JSONResponse(content={"message":"Login Success"})
    response.set_cookie(key="access_token", value=access_token)
    return response
