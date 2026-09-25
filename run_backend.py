import uvicorn
import sys
import os

# Ensure backend folder is on python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "backend"))

if __name__ == "__main__":
    print("=" * 60)
    print(" Starting AetherGuard AI SOC FastAPI & ML Backend")
    print(" Endpoint: http://127.0.0.1:8000")
    print(" Swagger Docs: http://127.0.0.1:8000/docs")
    print("=" * 60)
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)
