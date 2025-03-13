import os
import uvicorn

if __name__ == "__main__":
    try:
        port_env = os.environ.get("PORT", "8000")
        # Try to handle if PORT is passed with $ prefix accidentally
        if port_env.startswith('$'):
            port_env = port_env[1:]
            if not port_env:
                port_env = "8000"
        
        port = int(port_env)
        print(f"Starting server on port: {port}")
        uvicorn.run("client:app", host="0.0.0.0", port=port, reload=False)
    except Exception as e:
        print(f"Error starting server: {e}")
        # Fallback to a default port if there's any issue
        print("Falling back to default port 8000")
        uvicorn.run("client:app", host="0.0.0.0", port=8000, reload=False)