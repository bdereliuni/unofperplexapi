FROM python:3.9-slim

WORKDIR /app

# Sistem bağımlılıklarını yükle
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    libssl-dev \
    libffi-dev \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# pip'i güncelle
RUN pip install --no-cache-dir --upgrade pip

# Python bağımlılıklarını kopyala ve yükle
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Uygulama kodunu kopyala
COPY . .

# Port ayarı
ENV PORT=8000

# Uygulamayı çalıştır (inline Python komutu ile)
CMD ["python", "-c", "import os; import uvicorn; port = int(os.environ.get('PORT', '8000')); uvicorn.run('client:app', host='0.0.0.0', port=port)"]