import src.schemas as schemas
import src.models as models
import src.database as db
import src.utils as utils

from fastapi import FastAPI, Depends, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware

from sqlalchemy.orm import Session
from sqlalchemy import desc


db.Base.metadata.create_all(db.engine)
def get_session():
    session = db.SessionLocal()
    try:
        yield session
    finally:
        session.close()

app = FastAPI()

origins = [
    "http://localhost:3000"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

oauth2_scheme = utils.OAuth2PasswordBearerWithCookie(tokenUrl="/login")

@app.post("/login")
def login_user(response: Response, user: schemas.UserCreds, session: Session = Depends(get_session)):
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

    new_user = models.UserCreds(
        username=user.username, 
        password=encrypted_pwd,
        first_name=user.first_name,
        last_name=user.last_name,
        avatar_url=user.avatar_url,
        bio=user.bio)

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

@app.get("/profile/get-modules")
async def get_modules(session: Session = Depends(get_session), user: schemas.User = Depends(get_current_user)):
    if user:
        return session.query(models.Profile).filter(models.Profile.username == user.username).order_by(models.Profile.priority).all()
    else:
        raise HTTPException(status_code=401, detail="Invalid credentials. Please try again.")


@app.get("/profile/about")
async def get_about(session: Session = Depends(get_session), user: schemas.User = Depends(get_current_user)):
    if user:
        return session.query(models.Profile).filter(models.Profile.username == user.username).filter(models.Profile.section == 'about').order_by(models.Profile.priority).first()
    else:
        raise HTTPException(status_code=401, detail="Invalid credentials. Please try again.")

@app.get("/profile/links")
async def get_links(session: Session = Depends(get_session), user: schemas.User = Depends(get_current_user)):
    if user:
        return session.query(models.Profile).filter(models.Profile.username == user.username).filter(models.Profile.section == 'links').order_by(models.Profile.priority).all()
    else:
        raise HTTPException(status_code=401, detail="Invalid credentials. Please try again.")

@app.get("/logout")
async def logout(response: Response, request: Request, session: Session = Depends(get_session)):
    response.delete_cookie('access_token')
    return {"message": "User logged out."}

@app.post("/profile/edit")
async def edit(updated_user: schemas.BasicUser, response: Response, request: Request, user: schemas.User = Depends(get_current_user), session: Session = Depends(get_session)):
    existing_user = session.query(models.User).filter_by(username = user.username).first()
    if not existing_user:
        raise HTTPException(status_code=400, detail="Username could not be found!")

    existing_user.first_name = updated_user.first_name
    existing_user.last_name = updated_user.last_name
    existing_user.bio = updated_user.bio
    existing_user.avatar_url = updated_user.avatar_url

    session.commit()
    session.flush()

    return {"message": "User details updated successfully."}

@app.post("/profile/edit-about")
async def edit_about(about: schemas.About, response: Response, request: Request, user: schemas.User = Depends(get_current_user), session: Session = Depends(get_session)):
    user_about = session.query(models.Profile).filter_by(username = user.username).filter_by(section='about').first()

    if not user_about:
        about_obj = models.Profile(
            username=user.username, 
            section='about',
            title='about',
            body=about.about, 
            image_url=null, 
            priority=1,
            destination_url=null
        )
        session.add(about_obj)
    else:
        user_about.body = about.about

    session.commit()
    session.flush()

    return {"message": "About updated successfully."}

@app.post("/profile/add-link")
async def add_links(link: schemas.Link, response: Response, request: Request, user: schemas.User = Depends(get_current_user), session: Session = Depends(get_session)):
    existing_links = session.query(models.Profile).filter_by(username = user.username).filter_by(section='links').order_by(desc(models.Profile.priority)).first()
    pri = 1
    if existing_links:
        pri = existing_links.priority + 1
    
    linkObj = models.Profile(
        username=user.username, 
        section='links',
        title=link.title,
        body=link.body, 
        image_url=link.image_url, 
        priority=1,
        destination_url=link.destination_url
    )
    session.add(linkObj)
    session.commit()
    session.flush()

    return {"message": "Link added successfully."}


@app.delete("/profile/delete-link")
async def delete_link(link: schemas.DeleteLink, response: Response, request: Request, user: schemas.User = Depends(get_current_user), session: Session = Depends(get_session)):
    existing_link = session.query(models.Profile).filter_by(username = user.username).filter_by(section='links').filter_by(id=link.id).first()
    
    if existing_link:
        session.delete(existing_link)
    
    session.commit()
    session.flush()

    return {"message": "Link removed successfully."}

@app.get("/apps/get")
async def get_apps(availability: bool, response: Response, request: Request, user: schemas.User = Depends(get_current_user), session: Session = Depends(get_session)):
    return session.query(models.App).filter_by(availability=availability).all()

@app.get("/settings/get")
async def get_settings(response: Response, request: Request, user: schemas.User = Depends(get_current_user), session: Session = Depends(get_session)):
    return session.query(models.Setting).filter_by(username = user.username).all()


    