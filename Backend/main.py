from fastapi import FastAPI, Depends, HTTPException, status, Header
from .database import engine, Base, get_db
from sqlalchemy.orm import Session
from .models import User, Bin, UserBin
from .schema import UserCreated, UserResponse, TokenData, Status, UserBinCreated
from pwdlib import PasswordHash
from fastapi.security import OAuth2PasswordBearer
from typing import Annotated
from datetime import datetime, timedelta, timezone
import jwt
from jwt.exceptions import InvalidTokenError
import hmac
import hashlib
from fastapi.middleware.cors import CORSMiddleware
import os

app = FastAPI()
Base.metadata.create_all(bind=engine)

origins = [
    "http://localhost:8080",
    "http://localhost:3000",
    "https://binovate.vercel.app"
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

SECRET_KEY = os.getenv("SECRET_KEY")
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
    return { "access_token": access_token, "token_type": "bearer", "message" : "Login Success"}

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)], db: Session = Depends(get_db)): #ตรวจสอบว่ามี token หรือ token หมดอายุหรือยัง
    """Check Token Permission of user"""
    credentials_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials", headers={"WWW-Authenticate":"Bearer"})
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=ALGORITHM)
        username = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except InvalidTokenError:
        raise credentials_exception
    user = get_user(db, token_data.username)
    if user is None:
        raise credentials_exception
    return user

@app.get("/api/users/me", response_model=UserResponse) # ใช้ดึงเช็คข้อมูลจาก token แล้วเอาข้อมูลจาก token ไปหาใน database แล้วแมปเข้ากับ UserResponse ทำให้จะไมไ่ด้ password ออกมาด้วย
def read_users_me(current_user: Annotated[User, Depends(get_current_user)]):
    """API For get own data of each user"""
    if current_user:
        current_user.id = str(current_user.id)
    return current_user

SIGNATURE_SECRET = os.getenv("SECRET_KEY") #Signature Secret ของ header ที่มากับ request ของถังขยะ 
def verify_signature(signature, status):
    """Check Signature Of BinStatus API"""
    message = status.bin_id + status.timestamp
    expected_signature = hmac.new(SIGNATURE_SECRET.encode(), message.encode() ,hashlib.sha256).hexdigest() #Signature ของถังขยะมาจาก bin_id + timestamp มาบวกกันแล้วเข้ารหัสด้วย Secret เดียวกัน
    if not hmac.compare_digest(expected_signature, signature): #ถ้า Siganture ที่เข้ารหัสด้วย Secret เดียวกันตรงกันแปลว่า signature ที่ส่งมาถูก้อง
        return None
    return True

@app.put("/api/v1/binovate/status") #api สำหรับรับ request จากถังขยะ
async def update_status(body: Status, db: Session = Depends(get_db), signature: Annotated[str | None, Header(alias="signature")] = None):
    """API For Update Status of bin"""
    if not signature:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing signature")
    valid = verify_signature(signature, body)
    if valid is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid signature")
    bin = db.query(Bin).filter(Bin.bin_id == body.bin_id).first()
    if not bin: #กรณีที่ถังขยะเปิดใช้งานครั้งแรกและยังไม่่เคยมีในฐานข้อมูลแต่ Signature ที่ส่งมาถูกต้อง
        added_bin = Bin(bin_id=body.bin_id, status=body.status)
        db.add(added_bin)
        db.commit()
        db.refresh(added_bin)
        bin = added_bin
    bin.status = body.status
    db.commit()
    db.refresh(bin)
    return bin

@app.get("/api/v1/binovate/status") #API สำหรับให้ frontend ดึงไปใช้เพื่อดูถังขยะไหนเต็มบ้างโดยจะขึ้นแค่ถังขยะที่แสกนแล้ว
async def read_status(current_user : Annotated[User, Depends(get_current_user)], db: Session = Depends(get_db)):
    """API For user get status of bins"""
    if current_user:
        data = db.query(Bin).join(UserBin, Bin.bin_id == UserBin.bin_id).filter(UserBin.user_id == current_user.id).all()
        return data

@app.post("/api/v1/binovate/user/bins") #API สำหรับตอนที่ user ยิงมาเพื่อเพิ่มถังขยะใน list
async def create_user_bin(user_input: UserBinCreated, current_user : Annotated[User, Depends(get_current_user)], db: Session = Depends(get_db)):
    """API For add bin to user"""
    if current_user:
        bin = db.query(Bin).filter(Bin.bin_id == user_input.bin_id).first()
        if not bin:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Invalid code.")
        userbin = db.query(UserBin).filter(UserBin.bin_id == user_input.bin_id, UserBin.user_id == current_user.id).first()
        if userbin:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="You already have this bin.")
        added_userbin = UserBin(user_id=current_user.id, bin_id=user_input.bin_id)
        db.add(added_userbin)
        db.commit()
        db.refresh(added_userbin)
        return {"message" : "Success"}
