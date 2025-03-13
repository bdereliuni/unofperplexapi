# Perplexity API Sunucusu

Bu proje, [Perplexity AI](https://www.perplexity.ai/) servisine erişim sağlayan bir API sunucusudur.

## Özellikler

- Perplexity AI ile sorgu yapma
- Dosya yükleme desteği
- Pro hesap özelliklerine tam erişim
- Tüm Perplexity AI modellerini destekler (Claude, GPT-4o, vb.)

## Kullanım

API, iki ana endpoint üzerinden çalışır:

1. `/query` - Temel sorgu endpointi
2. `/query_with_files` - Dosya yükleme ile sorgu

## Kurulum

```bash
pip install -r requirements.txt
python client.py
```

## API Kullanım Örnekleri

### Temel Sorgu

```bash
curl -X POST http://localhost:8000/query -H "Content-Type: application/json" -d '{"query":"Yapay zeka nedir?","mode":"pro","model":"claude 3.7 sonnet","sources":["web"],"language":"tr-TR"}'
```

### Dosya ile Sorgu

Base64 ile kodlanmış dosya içeriği ile birlikte POST isteği gönderilir.

## Lisans

Bu proje açık kaynak olarak MIT lisansı altında yayınlanmıştır. 