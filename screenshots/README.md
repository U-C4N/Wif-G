# Screenshots

Bu klasör, README.md dosyasında kullanılacak ekran görüntüleri için ayrılmıştır.

## Eklenecek Görseller

1. **demo.gif** - Ana demo GIF'i (proje kök dizininde)
2. **network_scan.png** - Network tarama sonuçları
3. **port_scan.png** - Port tarama ve risk değerlendirmesi
4. **security_report.png** - Güvenlik analizi raporu
5. **optimization.png** - Optimizasyon önerileri

## GIF Oluşturma İpuçları

### Linux/macOS için:
```bash
# Terminal kaydı için asciinema kullan
asciinema rec demo.cast
asciinema upload demo.cast

# GIF'e çevirmek için
agg demo.cast demo.gif
```

### Windows için:
- **ScreenToGif**: https://www.screentogif.com/
- **LICEcap**: https://www.cockos.com/licecap/

## Ekran Görüntüsü Alma

```bash
# Programı çalıştır
sudo python3 main.py

# Çıktıyı kaydet
sudo python3 main.py | tee output.log
```

## Önerilen Boyutlar

- Demo GIF: 800x600 veya 1280x720
- Screenshots: 1920x1080 (tam ekran)
- Optimize edilmiş boyut: < 5MB per image
