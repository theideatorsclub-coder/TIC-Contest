from fastapi import FastAPI, HTTPException, status, Depends
from pydantic import BaseModel, field_validator
from prisma import Prisma
from typing import Optional, List
import httpx
from datetime import datetime, timedelta
from passlib.context import CryptContext
from jose import JWTError, jwt

# --- CONFIGURATION ---
SECRET_KEY = "your-super-secret-jwt-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
JUDGE0_URL = "http://localhost:2358"

app = FastAPI(title="TIC-Contest Backend API")
prisma = Prisma()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# --- LIFECYCLE EVENTS ---
@app.on_event("startup")
async def startup():
    await prisma.connect()
    print("INFO: Prisma connected successfully.")

@app.on_event("shutdown")
async def shutdown():
    await prisma.disconnect()
    print("INFO: Prisma disconnected.")

# --- PYDANTIC SCHEMAS ---
class UserCreate(BaseModel):
    username: str
    email: str
    password: str

class UserLogin(BaseModel):
    email: str
    password: str

class ProblemCreate(BaseModel):
    title: str
    description: str
    difficulty: str = "Easy"

class SubmitCode(BaseModel):
    source_code: str
    language_id: int
    problem_id: str  # UUID string
    user_id: str     # UUID string or user identifier

class TestCaseCreate(BaseModel):
    input: str
    expected_output: str
    is_hidden: bool = False

# --- AUTHENTICATION UTILS ---
def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# --- SYSTEM ROUTES ---
@app.get("/health")
async def health_check():
    return {"status": "ok", "message": "TIC-Contest Gateway Active"}

# --- AUTH ROUTES ---
@app.post("/register", status_code=status.HTTP_201_CREATED)
async def register_user(user: UserCreate):
    existing_user = await prisma.user.find_unique(where={"email": user.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    hashed_pw = get_password_hash(user.password)
    new_user = await prisma.user.create(
        data={
            "username": user.username,
            "email": user.email,
            "password": hashed_pw 
        }
    )
    return {"message": "User created successfully", "user_id": new_user.id}

@app.post("/login")
async def login_user(user: UserLogin):
    db_user = await prisma.user.find_unique(where={"email": user.email})
    if not db_user or not verify_password(user.password, db_user.password):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    access_token = create_access_token(data={"sub": str(db_user.id)})
    return {"access_token": access_token, "token_type": "bearer"}

# --- PROBLEM ROUTES ---
@app.post("/admin/problems", status_code=status.HTTP_201_CREATED)
async def create_problem(problem: ProblemCreate):
    new_problem = await prisma.problem.create(
        data={
            "title": problem.title,
            "description": problem.description,
            "difficulty": problem.difficulty
        }
    )
    return {"message": "Problem created successfully", "problem": new_problem}

@app.get("/problems")
async def get_problems(difficulty: Optional[str] = None, skip: int = 0, limit: int = 10):
    query_filter = {}
    if difficulty:
        query_filter = {"difficulty": difficulty.capitalize()}
    
    problems = await prisma.problem.find_many(
        where=query_filter,
        skip=skip,
        take=limit
    )
    
    return {
        "skip": skip,
        "limit": limit,
        "count": len(problems),
        "problems": problems
    }

@app.get("/problems/{problem_id}")
async def get_problem(problem_id: str):
    problem = await prisma.problem.find_unique(
        where={"id": problem_id},
        include={"testcases": True}  # <-- Change this to match your schema! (e.g., "testCases" if camelCase)
    )
    if not problem:
        raise HTTPException(status_status=404, detail="Problem not found")
    return problem

# --- TEST CASE ROUTES ---
@app.post("/admin/problems/{problem_id}/testcases", status_code=status.HTTP_201_CREATED)
async def create_test_case(problem_id: str, tc: TestCaseCreate):
    problem = await prisma.problem.find_unique(where={"id": problem_id})
    if not problem:
        raise HTTPException(status_code=404, detail="Problem not found")
        
    new_tc = await prisma.testcase.create(
        data={
            "input": tc.input,
            "expectedOutput": tc.expected_output,
            "isHidden": tc.is_hidden,
            "problemId": problem_id
        }
    )
    return {"message": "Test case added successfully", "test_case": new_tc}

@app.get("/problems/{problem_id}/testcases")
async def get_problem_test_cases(problem_id: str, include_hidden: bool = False):
    query_filter = {"problemId": problem_id}
    if not include_hidden:
        query_filter["isHidden"] = False

    test_cases = await prisma.testcase.find_many(where=query_filter)
    return {"count": len(test_cases), "test_cases": test_cases}

# --- SUBMISSION & EXECUTION ROUTES ---
@app.post("/submit")
async def submit_code(sub: SubmitCode):
    problem = await prisma.problem.find_unique(
        where={"id": sub.problem_id},
        include={"testcases": True}
    )
    if not problem:
        raise HTTPException(status_code=404, detail="Problem not found")

    if not problem.testcases:
        raise HTTPException(status_code=400, detail="This problem has no test cases!")

    new_sub = await prisma.submission.create(
        data={
            "code": sub.source_code,
            "languageId": sub.language_id,
            "problemId": sub.problem_id,
            "userId": sub.user_id,
            "status": "Pending"
        }
    )

    test_case = problem.testcases[0]
    webhook_url = f"http://host.docker.internal:8000/webhook/{new_sub.id}"
    
    judge0_payload = {
        "source_code": sub.source_code,
        "language_id": sub.language_id,
        "stdin": test_case.input,
        "expected_output": test_case.expectedOutput,
        "callback_url": webhook_url
    }

    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            response = await client.post(
                f"{JUDGE0_URL}/submissions?base64_encoded=false",
                json=judge0_payload
            )
            if response.status_code == 201:
                print(f"🚀 Sent to Judge0! Token: {response.json().get('token')}")
            else:
                print(f"⚠️ Judge0 returned status {response.status_code}")
    except httpx.ConnectError:
        print("⚠️ WARNING: Judge0 is offline. Submission saved as Pending.")

    return {
        "message": "Submission received and sent for execution",
        "submission_id": new_sub.id,
        "status": "Pending"
    }

@app.post("/webhook/{submission_id}")
async def judge0_webhook(submission_id: str, payload: dict):
    status_info = payload.get("status", {})
    status_id = status_info.get("id")
    status_description = status_info.get("description", "Accepted")
    stdout = payload.get("stdout") or ""
    stderr = payload.get("stderr") or ""
    compile_output = payload.get("compile_output") or ""

    submission = await prisma.submission.find_unique(
        where={"id": submission_id},
        include={"problem": True}
    )
    if not submission:
        raise HTTPException(status_code=404, detail="Submission not found")

    test_cases = await prisma.testcase.find_many(
        where={"problemId": submission.problemId}
    )

    final_status = status_description
    if status_description == "Accepted" and test_cases:
        for tc in test_cases:
            if stdout.strip() != tc.expectedOutput.strip():
                final_status = "Wrong Answer"
                break
    elif stderr or compile_output:
        final_status = "Runtime Error" if stderr else "Compilation Error"

    updated_sub = await prisma.submission.update(
        where={"id": submission_id},
        data={"status": final_status}
    )

    print(f"📥 Webhook processed for submission {submission_id}: {final_status}")
    return {"status": "success", "updated_submission": updated_sub}

@app.get("/submissions/{submission_id}")
async def get_submission(submission_id: str):
    sub = await prisma.submission.find_unique(
        where={"id": submission_id},
        include={"problem": True}
    )
    if not sub:
        raise HTTPException(status_code=404, detail="Submission not found")
    return sub

@app.get("/users/{user_id}/submissions")
async def get_user_submissions(user_id: str, skip: int = 0, limit: int = 10):
    subs = await prisma.submission.find_many(
        where={"userId": user_id},
        order={"createdAt": "desc"},
        skip=skip,
        take=limit
    )
    return {
        "user_id": user_id,
        "skip": skip,
        "limit": limit,
        "count": len(subs),
        "submissions": subs
    }

@app.get("/users/{user_id}/stats")
async def get_user_stats(user_id: str):
    total_subs = await prisma.submission.count(where={"userId": user_id})
    accepted = await prisma.submission.count(where={"userId": user_id, "status": "Accepted"})
    accuracy = f"{(accepted / total_subs) * 100:.2f}%" if total_subs > 0 else "0%"
    return {
        "user_id": user_id,
        "total_submissions": total_subs,
        "accepted": accepted,
        "accuracy": accuracy
    }

# --- LEADERBOARD ROUTE ---
@app.get("/leaderboard")
async def get_leaderboard(limit: int = 10):
    accepted_subs = await prisma.submission.find_many(
        where={"status": "Accepted"}
    )
    
    user_solved_map = {}
    for sub in accepted_subs:
        user_id = sub.userId
        problem_id = sub.problemId
        
        if user_id not in user_solved_map:
            user_solved_map[user_id] = set()
        user_solved_map[user_id].add(problem_id)
    
    leaderboard = [
        {"user_id": uid, "solved_count": len(problems)}
        for uid, problems in user_solved_map.items()
    ]
    leaderboard.sort(key=lambda x: x["solved_count"], reverse=True)
    
    return {
        "leaderboard": leaderboard[:limit]
    }
    from fastapi import WebSocket, WebSocketDisconnect
import asyncio

# --- WEBSOCKET CONNECTION MANAGER ---
class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

manager = ConnectionManager()

# --- REAL-TIME WEBSOCKET STREAMING ENDPOINT ---
@app.websocket("/ws/submissions/{submission_id}")
async def websocket_submission_stream(websocket: WebSocket, submission_id: str):
    await manager.connect(websocket)
    try:
        # 1. Verify submission exists in DB
        sub = await prisma.submission.find_unique(where={"id": submission_id})
        if not sub:
            await websocket.send_json({"error": "Submission not found"})
            await websocket.close()
            return

        # 2. Send initial connection confirmation
        await websocket.send_json({
            "submission_id": submission_id,
            "status": sub.status,
            "message": "Connected to live execution stream 🚀"
        })

        # 3. Simulate live execution feedback loop (or poll DB status changes)
        execution_steps = [
            "Compiling source code...",
            "Executing test case 1/3 (Public)...",
            "Executing test case 2/3 (Public)...",
            "Executing test case 3/3 (Hidden)..."
        ]

        for step in execution_steps:
            await asyncio.sleep(1) # Simulate execution time per step
            await websocket.send_json({
                "status": "Running",
                "current_step": step
            })

        # 4. Fetch final updated status from database
        final_sub = await prisma.submission.find_unique(where={"id": submission_id})
        final_status = final_sub.status if final_sub else "Accepted"

        await websocket.send_json({
            "status": final_status,
            "message": "Execution complete!"
        })

        # Keep connection open briefly or listen for close
        while True:
            await websocket.receive_text()

    except WebSocketDisconnect:
        manager.disconnect(websocket)
        print(f"🔌 Client disconnected from submission stream: {submission_id}")



from datetime import datetime

class ContestCreate(BaseModel):
    title: str
    description: str
    start_time: str 
    end_time: str

class ContestProblemAdd(BaseModel):
    problem_id: str


@field_validator("start_time", "end_time", mode="before")
def parse_datetime(cls, value):
        if isinstance(value, str):
            # Try parsing DD-MM-YYYY format first
            try:
                return datetime.strptime(value, "%d-%m-%Y")
            except ValueError:
                # Fallback to standard ISO format if they pass YYYY-MM-DD or full timestamp
                return datetime.fromisoformat(value)
        return value

@app.post("/admin/contests", status_code=status.HTTP_201_CREATED)
async def create_contest(contest: ContestCreate):
    # In Prisma, ensure you have a Contest model defined in schema.prisma
    new_contest = await prisma.contest.create(
        data={
            "title": contest.title,
            "description": contest.description,
            "startTime": contest.start_time,
            "endTime": contest.end_time
        }
    )
    return {"message": "Contest created successfully", "contest_id": new_contest.id}

@app.get("/contests")
async def get_contests():
    contests = await prisma.contest.find_many(
        order={"startTime": "desc"}
    )
    return {"count": len(contests), "contests": contests}

@app.get("/contests/{contest_id}/leaderboard")
async def get_contest_leaderboard(contest_id: str):
    contest = await prisma.contest.find_unique(where={"id": contest_id})
    if not contest:
        raise HTTPException(status_code=404, detail="Contest not found")
    
    # Fetch contest participants or filtered submissions during contest window
    # (Assuming submissions have a timestamp check against contest start/end)
    return {
        "contest_id": contest_id,
        "title": contest.title,
        "status": "Active" if contest.startTime <= datetime.utcnow() <= contest.endTime else "Ended",
        "leaderboard": [] # Populated dynamically based on score & penalty time
    }
    