E-mail Analyzer CLI Tool

Bu CLI (Command Line Interface) aracı, .eml dosyalarını analiz etmek ve 
e-posta güvenliği hakkında bilgi sağlamak için kullanılır.

Kullanım

1. Öncelikle Python'u yükleyin: Python İndirme Sayfası

2. Proje klasörünüzde sanal bir ortam oluşturun (isteğe bağlı):

   python -m venv venv

3. Sanal ortamı etkinleştirin (isteğe bağlı):

   - Windows için:

     venv\Scripts\activate

   - macOS ve Linux için:

     source venv/bin/activate

4. Gerekli bağımlılıkları yükleyin:

   pip install -r requirements.txt

5. E-posta dosyasını analiz etmek için aşağıdaki komutu kullanın:

   python emlanalyze.py sample.eml

Özellikler

- E-posta dosyasının genel bilgilerini görüntüleme
- .eml dosyasının içeriğindeki URL'leri analiz etme
- Eklerin MD5, SHA1 ve SHA256 hash değerlerini görüntüleme
- Eklerin Virustotal tarafından analiz sonuçlarını görüntüleme
- İleti içeriğindeki URL'leri Virustotal'de sorgulama
- Temel güvenlik kontrollerini gerçekleştirme
- E-posta gönderen ve alıcı adreslerini karşılaştırma

Lisans

Bu proje MIT lisansı altında lisanslanmıştır. Daha fazla bilgi için 
LICENSE.md dosyasına başvurun.

