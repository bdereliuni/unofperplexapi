# Perplexity API Server

Bu proje, Perplexity AI API'sine erişim sağlayan bir proxy API sunucusudur. FastAPI ile geliştirilmiştir ve kullanıcılara Perplexity AI'nin güçlü dil modellerine erişim imkanı sağlar.

## Özellikler

- Perplexity AI API'ye HTTP istekleri göndermek için kolay bir arabirim
- Pro modellerine erişim (claude 3.7 sonnet, gpt-4o, vb.)
- Dosya yükleme desteği
- Sürekli sohbet desteği (chat_id parametresi ile)
- Veritabanında güvenli ve kalıcı veri saklama

## Kurulum

1. Repo'yu klonlayın:
```bash
git clone https://github.com/username/perplexity-api-server.git
cd perplexity-api-server
```

2. Gerekli paketleri yükleyin:
```bash
pip install -r requirements.txt
```

3. Uygulamayı başlatın:
```bash
uvicorn client:app --host 0.0.0.0 --port 8000 --reload
```

## Railway'de Çalıştırma

Bu projeyi Railway'de çalıştırmak için:

1. Railway hesabınızda yeni bir proje oluşturun
2. GitHub reponuzu bağlayın
3. PostgreSQL eklentisini ekleyin
4. Uygulama otomatik olarak Railway'de dağıtılacaktır

## Veritabanı Migrasyonları

Veritabanı şemasını oluşturmak veya güncellemek için Alembic kullanabilirsiniz:

```bash
# Mevcut veritabanını güncellemek için
alembic upgrade head

# Yeni bir migrasyon oluşturmak için
alembic revision --autogenerate -m "Migration açıklaması"
```

## API Kullanımı

### Sorgu Gönderme

```bash
curl -X POST http://localhost:8000/query -H "Content-Type: application/json" -d '{
  "query": "Merhaba, nasılsın?",
  "mode": "pro",
  "model": "claude 3.7 sonnet",
  "sources": ["web"],
  "language": "tr-TR",
  "chat_id": "benzersiz-sohbet-id"
}'
```

### Sohbeti Devam Ettirme

Aynı `chat_id` ile yeni bir sorgu göndererek sohbeti devam ettirebilirsiniz:

```bash
curl -X POST http://localhost:8000/query -H "Content-Type: application/json" -d '{
  "query": "Önceki soruma ek olarak...",
  "mode": "pro",
  "model": "claude 3.7 sonnet",
  "sources": ["web"],
  "language": "tr-TR",
  "chat_id": "benzersiz-sohbet-id"
}'
```

### Sohbetleri Listeleme

```bash
curl http://localhost:8000/chats
```

### Belirli Bir Sohbeti Görüntüleme

```bash
curl http://localhost:8000/chats/benzersiz-sohbet-id
```

### Bir Sohbeti Silme

```bash
curl -X DELETE http://localhost:8000/chats/benzersiz-sohbet-id
```

## Güvenlik ve Kalıcılık

Bu API, sohbet verilerini güvenli bir şekilde PostgreSQL veritabanında saklar. Bu sayede:

1. Sunucu yeniden başlatıldığında veriler kaybolmaz
2. Veriler yapılandırılmış bir şekilde saklanır ve sorgulanabilir
3. Veri bütünlüğü korunur (ilişkisel veritabanı avantajları)
4. Railway'in sağladığı veritabanı yedekleme özellikleri kullanılabilir

## Güvenlik İyileştirmeleri

Uygulama şu anda temel düzeyde bir güvenlik sağlamaktadır. Prodüksiyonda aşağıdaki güvenlik önlemlerini eklemeyi düşünebilirsiniz:

- API anahtarı doğrulama eklemek
- Rate limiting uygulamak
- CORS politikalarını sıkılaştırmak
- HTTPS zorunlu kılmak

## Katkıda Bulunma

Katkılarınızı bekliyoruz! Lütfen pull request göndermeden önce değişikliklerinizi test edin.

## Lisans

MIT 