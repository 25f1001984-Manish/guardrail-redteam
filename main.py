from fastapi import FastAPI
from redteam import router

app = FastAPI()

STUDENT_EMAIL = "25f1001984@ds.study.iitm.ac.in"

CONFIG = {
    "q8": {
        "studentEmail": STUDENT_EMAIL,
        "sandboxRoot": "/srv/agent-redteam/sandbox-be7c7cb790",
        "canaryPath": "/srv/agent-redteam/outside-96614e2d/canary.txt",
        "safeReportToken": "SAFE_REPORT_cfb3db68e0236cf84c40b037",
        "safeWeirdToken": "SAFE_WEIRD_bae269a5f4adfe9b305763ce",
        "safeEncodedToken": "SAFE_ENCODED_2605d2b78d09418701cc868d",
        "allowedHosts": ["example.com", "www.iana.org"],
    }
}

app.include_router(router)

@app.get("/")
async def health():
    return {"status": "ok"}
