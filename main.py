
from fastapi import FastAPI, HTTPException, Header, Depends
from typing import List, Optional
from datetime import datetime, timedelta
from hashlib import sha256
from uuid import uuid4
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, EmailStr, Field
from bson import ObjectId
import redis.asyncio as redis  # Redis client for asyncio
import json  # To serialize data for caching
import jwt  # PyJWT
import os

from models import UserRegister, UserLogin, TodoBase, TodoUpdate, TodoResponse

app = FastAPI()

# MongoDB Setup
client = AsyncIOMotorClient("mongodb://localhost:27017")
db = client.todo_db
todo_collection = db.todos
user_collection = db.users

# Redis Setup
redis_client = redis.Redis(host='localhost', port=6379, decode_responses=True)

# JWT Setup
JWT_SECRET = os.getenv("JWT_SECRET", "mysecret")  # You can store this securely
JWT_ALGORITHM = "HS256"
JWT_EXP_DELTA_MINUTES = 60

#  Helpers 

def hash_password(password: str) -> str:
    return sha256(password.encode()).hexdigest()

def create_jwt(email: str):
    payload = {
        "email": email,
        "exp": datetime.utcnow() + timedelta(minutes=JWT_EXP_DELTA_MINUTES)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def decode_jwt(token: str):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload["email"]
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None

async def get_current_user(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Unauthorized")
    token = authorization.split(" ")[1]
    email = decode_jwt(token)
    if not email:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return email

#  Auth Routes 

@app.post("/register")
async def register(user: UserRegister):
    existing = await user_collection.find_one({"email": user.email})
    if existing:
        raise HTTPException(status_code=409, detail="Email already registered")

    user_dict = user.dict()
    user_dict["password"] = hash_password(user.password)
    await user_collection.insert_one(user_dict)
    return {"message": "User registered successfully"}

@app.post("/login")
async def login(data: UserLogin):
    hashed = hash_password(data.password)
    user = await user_collection.find_one({"email": data.email, "password": hashed})
    if user:
        token = create_jwt(data.email)
        return {"message": "Login successful", "token": token}
    raise HTTPException(status_code=401, detail="Invalid credentials")

#  Todo Route

@app.get("/")
async def home():
    return {"message": "Todo API is working"}

@app.get("/todos", response_model=List[TodoResponse])
async def get_todos(user=Depends(get_current_user)):
    cache_key = f"todos:{user}"
    try:
        cached_data = await redis_client.get(cache_key)
        if cached_data:
            return json.loads(cached_data)
    except Exception as e:
        print("Redis get error:", e)

    todos = await todo_collection.find().to_list(1000)
    for todo in todos:
        todo["_id"] = str(todo["_id"])

    try:
        await redis_client.set(cache_key, json.dumps(todos), ex=60)  # Cache for 1 minute
    except Exception as e:
        print("Redis set error:", e)
    return todos

@app.post("/todos", response_model=TodoResponse)
async def add_todo(todo: TodoBase, user=Depends(get_current_user)):
    todo_dict = todo.dict()
    if todo_dict.get("due"):
        try:
            datetime.strptime(todo_dict["due"], "%Y-%m-%d %H:%M")
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid date format")

    result = await todo_collection.insert_one(todo_dict)
    todo_dict["_id"] = str(result.inserted_id)

    try:
        await redis_client.delete(f"todos:{user}")
    except Exception as e:
        print("Redis delete error:", e)
    return todo_dict

@app.put("/todos/{todo_id}", response_model=TodoResponse)
async def update_todo(todo_id: str, updated_todo: TodoUpdate, user=Depends(get_current_user)):
    update_data = {k: v for k, v in updated_todo.dict().items() if v is not None}
    result = await todo_collection.update_one({"_id": ObjectId(todo_id)}, {"$set": update_data})
    if result.matched_count:
        todo = await todo_collection.find_one({"_id": ObjectId(todo_id)})
        todo["_id"] = str(todo["_id"])

        try:
            await redis_client.delete(f"todos:{user}")
        except Exception as e:
            print("Redis delete error:", e)
        return todo
    raise HTTPException(status_code=404, detail="Todo not found")

@app.delete("/todos/{todo_id}")
async def delete_todo(todo_id: str, user=Depends(get_current_user)):
    result = await todo_collection.delete_one({"_id": ObjectId(todo_id)})
    if result.deleted_count:
        try:
            await redis_client.delete(f"todos:{user}")
        except Exception as e:
            print("Redis delete error:", e)
        return {"message": "Todo deleted"}
    raise HTTPException(status_code=404, detail="Todo not found")

@app.get("/todos/filter", response_model=List[TodoResponse])
async def filter_todos(completed: bool, user=Depends(get_current_user)):
    todos = await todo_collection.find({"completed": completed}).to_list(1000)
    for todo in todos:
        todo["_id"] = str(todo["_id"])
    return todos

# ---------- AI Scheduler ----------

@app.get("/ai/schedule", response_model=List[TodoResponse])
async def generate_schedule(user=Depends(get_current_user)):
    def priority_value(p):
        return {"high": 1, "medium": 2, "low": 3}.get(p.lower(), 2)

    todos = await todo_collection.find({"completed": False}).to_list(1000)

    for todo in todos:
        todo["_id"] = str(todo["_id"])

    def sort_key(task):
        due = task.get("due")
        due_dt = datetime.strptime(due, "%Y-%m-%d %H:%M") if due else datetime.max
        return (priority_value(task.get("priority", "medium")), due_dt)

    sorted_tasks = sorted(todos, key=sort_key)
    return sorted_tasks
