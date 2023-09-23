import src.schemas as schemas
import src.models as models
import src.database as db
import src.utils as utils

from fastapi import FastAPI, Depends, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware

from sqlalchemy.orm import Session


db.Base.metadata.create_all(db.engine)
def get_session():
    session = db.SessionLocal()
    try:
        yield session
    finally:
        session.close()

app = FastAPI()

origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

oauth2_scheme = utils.OAuth2PasswordBearerWithCookie(tokenUrl="/login")

@app.post("/login")
def login_user(response: Response, request: Request, user: schemas.User, session: Session = Depends(get_session)):
    db_user = session.query(models.UserCreds).filter_by(username = user.username).first()
    if not db_user:
        raise HTTPException(status_code=400, detail="Username could not be found. Please try again.")
    if utils.check_hashed_pwd(user.password, db_user.password):
            access_token = utils.create_access_token(user.username)
            utils.create_cookie(response, 'access_token', access_token)
            return {
                "access_token": access_token,
                "refresh_token": utils.create_refresh_token(user.username),
            }
    else:
        raise HTTPException(status_code=400, detail="Password did not match. Please try again.")


@app.post("/register")
def register_user(user: schemas.User, session: Session = Depends(get_session)):
    existing_user = session.query(models.User).filter_by(username = user.username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already exists!")
    
    encrypted_pwd = utils.get_hashed_pwd(user.password)

    new_user = models.UserCreds(username=user.username, password=encrypted_pwd)

    session.add(new_user)
    session.commit()
    session.refresh(new_user)
        
    return {"message": "User created successfully!"}

async def get_current_user(response: Response, request: Request, session: Session = Depends(get_session), token=Depends(oauth2_scheme)):
    try:
        payload = utils.decode_token(token)
        db_user = session.query(models.User).filter_by(username = payload['sub']).first()
        return db_user
    except:
        raise HTTPException(status_code=401, detail="Invalid credentials. Please try again.")

@app.get("/profile/get")
async def get_profile(session: Session = Depends(get_session), user: schemas.User = Depends(get_current_user)):
    if user:
        return user
    else:
        raise HTTPException(status_code=401, detail="Invalid credentials. Please try again.")



