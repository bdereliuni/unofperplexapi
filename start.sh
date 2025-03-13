#!/bin/bash

# PORT environment variable'ını kontrol et, yoksa varsayılan 8000'i kullan
PORT="${PORT:-8000}"

# Uygulamayı başlat
exec uvicorn client:app --host 0.0.0.0 --port "$PORT" 