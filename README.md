# Log Analiz Aracı

Apache/Nginx biçimindeki access log dosyalarını çevrimdışı inceleyen küçük bir Python CLI aracı. Tekrarlanan 401/403 yanıtlarını, 404 yoğunluğunu ve sık görülen hassas yol denemelerini özetler.

## Gereksinimler

- Python 3.10 veya üzeri
- Harici paket gerekmez

## Kullanım

```bash
python log_analyzer.py sample_access.log
python log_analyzer.py sample_access.log --failed-threshold 3
python log_analyzer.py sample_access.log --json
```

Aracı yalnızca inceleme iznin olan loglarda kullan. IP adresleri raporda görünür; raporu paylaşmadan önce gizlilik gereksinimlerini kontrol et.

## Kapsam ve sınırlamalar

Bu, imza ve eşik tabanlı bir ön incelemedir. Normal bir kullanıcı da çok sayıda 404 oluşturabilir; bulgular tek başına saldırı kanıtı değildir. JSON seçeneği çıktıyı ekrana yazar, dosyaya kaydetmez.

## Yapay zekâ desteği

Bu proje, yapay zekâ desteğiyle geliştirildi ve düzenlendi.

## Lisans

MIT
