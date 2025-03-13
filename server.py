import os
import uvicorn
from client import app

if __name__ == "__main__":
    try:
        port_str = os.environ.get("PORT", "8000")
        port = int(port_str)
        print(f"Starting server on port: {port}")
        uvicorn.run(app, host="0.0.0.0", port=port)
    except Exception as e:
        print(f"Error starting server: {e}")
        print("Falling back to default port 8000")
        uvicorn.run(app, host="0.0.0.0", port=8000)
