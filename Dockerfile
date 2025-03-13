FROM python:3.9-slim

WORKDIR /app

# Sistem bağımlılıklarını yükle
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Python bağımlılıklarını kopyala ve yükle
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Uygulama kodunu kopyala
COPY . .

# Port ayarı
ENV PORT=8000

# Uygulamayı çalıştır
CMD ["uvicorn", "client:app", "--host", "0.0.0.0", "--port", "8000"] 