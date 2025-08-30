# ! Bu araç @keyiflerolsun tarafından | @KekikAkademi için yazılmıştır.

from Kekik.cli    import konsol
from cloudscraper import CloudScraper
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import os, re, base64, json

class MainUrlUpdater:
    def __init__(self, base_dir="."):
        self.base_dir = base_dir
        self.oturum   = CloudScraper()

    @property
    def eklentiler(self):
        return sorted([
            dosya for dosya in os.listdir(self.base_dir)
                if os.path.isdir(os.path.join(self.base_dir, dosya))
                    and not dosya.startswith(".")
                        and dosya not in {"gradle", "CanliTV", "OxAx", "__Temel", "SineWix", "YouTube", "NetflixMirror", "HQPorner"}
        ])

    def _kt_dosyasini_bul(self, dizin, dosya_adi):
        for kok, alt_dizinler, dosyalar in os.walk(dizin):
            if dosya_adi in dosyalar:
                return os.path.join(kok, dosya_adi)

        return None

    @property
    def kt_dosyalari(self):
        return [
            kt_dosya_yolu for eklenti in self.eklentiler
                if (kt_dosya_yolu := self._kt_dosyasini_bul(eklenti, f"{eklenti}.kt"))
        ]

    def _mainurl_bul(self, kt_dosya_yolu):
        with open(kt_dosya_yolu, "r", encoding="utf-8") as file:
            icerik = file.read()
            if mainurl := re.search(r'override\s+var\s+mainUrl\s*=\s*"([^"]+)"', icerik):
                return mainurl[1]

        return None

    def _mainurl_guncelle(self, kt_dosya_yolu, eski_url, yeni_url):
        with open(kt_dosya_yolu, "r+", encoding="utf-8") as file:
            icerik = file.read()
            yeni_icerik = icerik.replace(eski_url, yeni_url)
            file.seek(0)
            file.write(yeni_icerik)
            file.truncate()

    def _versiyonu_artir(self, build_gradle_yolu):
        with open(build_gradle_yolu, "r+", encoding="utf-8") as file:
            icerik = file.read()
            if version_match := re.search(r'version\s*=\s*(\d+)', icerik):
                eski_versiyon = int(version_match[1])
                yeni_versiyon = eski_versiyon + 1
                yeni_icerik = icerik.replace(f"version = {eski_versiyon}", f"version = {yeni_versiyon}")
                file.seek(0)
                file.write(yeni_icerik)
                file.truncate()
                return yeni_versiyon

        return None

    def _rectv_ver(self):
        istek = self.oturum.post(
            url     = "https://firebaseremoteconfig.googleapis.com/v1/projects/791583031279/namespaces/firebase:fetch",
            headers = {
                "X-Goog-Api-Key"    : "AIzaSyBbhpzG8Ecohu9yArfCO5tF13BQLhjLahc",
                "X-Android-Package" : "com.rectv.shot",
                "User-Agent"        : "Dalvik/2.1.0 (Linux; U; Android 12)",
            },
            json    = {
                "appBuild"      : "81",
                "appInstanceId" : "evON8ZdeSr-0wUYxf0qs68",
                "appId"         : "1:791583031279:android:1",
            }
        )
        return istek.json().get("entries", {}).get("api_url", "").replace("/api/", "")

    def _golgetv_ver(self):
        istek = self.oturum.get("https://raw.githubusercontent.com/sevdaliyim/sevdaliyim/main/ssl2.key").text
        cipher = AES.new(b"trskmrskslmzbzcnfstkcshpfstkcshp", AES.MODE_CBC, b"trskmrskslmzbzcn")
        encrypted_data = base64.b64decode(istek)
        decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size).decode("utf-8")
        return json.loads(decrypted_data, strict=False)["apiUrl"]

    def _inatbox_ver(self):
        """InatBox için özel URL kontrolü - AES şifreleme ile"""
        try:
            # Script'inizdeki URL'den veri çek
            URL = "https://static.staticsave.com/conn/ct.js"
            MASTER_KEY = "ywevqtjrurkwtqgz"
            SEPARATOR = ":"

            response = self.oturum.get(URL, timeout=30)
            response.raise_for_status()

            # İlk parçayı al
            data = response.text.split(SEPARATOR)[0]

            # İlk AES çözme işlemi
            decoded = base64.b64decode(data)
            key = MASTER_KEY.encode('utf-8')
            cipher = AES.new(key, AES.MODE_CBC, key)  # IV = Key
            decrypted = unpad(cipher.decrypt(decoded), AES.block_size)

            # İkinci parçayı al ve tekrar çöz
            data2 = decrypted.decode('utf-8', errors='ignore').split(SEPARATOR)[0]
            decoded2 = base64.b64decode(data2)
            cipher2 = AES.new(key, AES.MODE_CBC, key)  # IV = Key
            decrypted2 = unpad(cipher2.decrypt(decoded2), AES.block_size)

            final_data = decrypted2.decode('utf-8', errors='ignore')

            # JSON parse et
            try:
                json_data = json.loads(final_data)
            except json.JSONDecodeError:
                # JSON bulma fonksiyonu
                json_match = re.search(r'(\[.*\])', final_data, re.DOTALL)
                if json_match:
                    try:
                        json_data = json.loads(json_match.group(1))
                    except json.JSONDecodeError:
                        json_match = re.search(r'(\{.*\})', final_data, re.DOTALL)
                        if json_match:
                            json_data = json.loads(json_match.group(1))
                        else:
                            raise ValueError("JSON bulunamadı")
                else:
                    raise ValueError("JSON bulunamadı")

            # contentUrl ve spor_url değerlerini çıkar
            if isinstance(json_data, list):
                content_url = ""
                spor_url = ""

                for item in json_data:
                    if item.get('catName') == 'Liste 1 - TR':
                        content_url = item.get('catHost', '')
                    elif item.get('catName') == 'Spor':
                        spor_url = item.get('catUrl', '')

                # Sonuçları döndür
                result = {}
                if content_url:
                    result['content_url'] = f"https://{content_url}"
                if spor_url:
                    result['spor_url'] = spor_url

                if result:
                    return result
                else:
                    raise ValueError("Hiçbir URL bulunamadı")
            else:
                raise ValueError("Geçersiz JSON formatı")

        except Exception as hata:
            # Yedek yöntem - basit URL kontrolü
            try:
                # Mevcut URL'leri test et
                test_content_urls = [
                    "https://dizibox.cfd",
                    "https://dizibox.com",
                    "https://dizibox.net",
                    "https://dizibox.rest"
                ]

                test_spor_urls = [
                    "https://boxyz.cfd/CDN/001_STR/boxyz.cfd/spor_v2.php",
                    "https://boxyz.com/CDN/001_STR/boxyz.com/spor_v2.php",
                    "https://boxyz.net/CDN/001_STR/boxyz.net/spor_v2.php"
                ]

                working_content_url = None
                working_spor_url = None

                for url in test_content_urls:
                    try:
                        istek = self.oturum.get(url, timeout=10)
                        if istek.status_code == 200:
                            working_content_url = url
                            break
                    except:
                        continue

                for url in test_spor_urls:
                    try:
                        istek = self.oturum.get(url, timeout=10)
                        if istek.status_code == 200:
                            working_spor_url = url
                            break
                    except:
                        continue

                if working_content_url or working_spor_url:
                    result = {}
                    if working_content_url:
                        result['content_url'] = working_content_url
                    if working_spor_url:
                        result['spor_url'] = working_spor_url
                    return result

                raise ValueError("Çalışan URL bulunamadı")

            except Exception as yedek_hata:
                raise hata

    def _inatbox_guncelle(self, kt_dosya_yolu, eski_urls, yeni_urls):
        """InatBox için hem contentUrl hem spor URL'ini güncelle"""
        with open(kt_dosya_yolu, "r+", encoding="utf-8") as file:
            icerik = file.read()

            # contentUrl güncellemesi
            if 'content_url' in yeni_urls and 'content_url' in eski_urls:
                icerik = icerik.replace(eski_urls['content_url'], yeni_urls['content_url'])

            # spor URL güncellemesi
            if 'spor_url' in yeni_urls and 'spor_url' in eski_urls:
                icerik = icerik.replace(eski_urls['spor_url'], yeni_urls['spor_url'])

            file.seek(0)
            file.write(icerik)
            file.truncate()

    def _inatbox_url_bul(self, kt_dosya_yolu):
        """InatBox için hem contentUrl hem spor URL'ini bul"""
        with open(kt_dosya_yolu, "r", encoding="utf-8") as file:
            icerik = file.read()

            urls = {}

            # contentUrl bul
            content_match = re.search(r'contentUrl\s*=\s*"([^"]+)"', icerik)
            if content_match:
                urls['content_url'] = content_match[1]

            # spor URL bul
            spor_match = re.search(r'"(https://[^"]*spor_v2\.php)"', icerik)
            if spor_match:
                urls['spor_url'] = spor_match[1]

            return urls

    @property
    def mainurl_listesi(self):
        return {
            dosya: self._mainurl_bul(dosya) for dosya in self.kt_dosyalari
        }

    def guncelle(self):
        for dosya, mainurl in self.mainurl_listesi.items():
            eklenti_adi = dosya.split("/")[0]

            print("\n")
            konsol.log(f"[~] Kontrol Ediliyor : {eklenti_adi}")
            if eklenti_adi == "RecTV":
                try:
                    final_url = self._rectv_ver()
                    konsol.log(f"[+] Kontrol Edildi   : {mainurl}")
                except Exception as hata:
                    konsol.log(f"[!] Kontrol Edilemedi : {mainurl}")
                    konsol.log(f"[!] {type(hata).__name__} : {hata}")
                    continue
            elif eklenti_adi == "GolgeTV":
                try:
                    final_url = self._golgetv_ver()
                    konsol.log(f"[+] Kontrol Edildi   : {mainurl}")
                except Exception as hata:
                    konsol.log(f"[!] Kontrol Edilemedi : {mainurl}")
                    konsol.log(f"[!] Kontrol Edilemedi : {mainurl}")
                    konsol.log(f"[!] {type(hata).__name__} : {hata}")
                    continue
            elif eklenti_adi == "InatBox":
                try:
                    # InatBox için özel URL kontrolü
                    urls = self._inatbox_ver()
                    mevcut_urls = self._inatbox_url_bul(dosya)

                    konsol.log(f"[+] Content URL      : {mevcut_urls.get('content_url', 'Bulunamadı')}")
                    konsol.log(f"[+] Spor URL         : {mevcut_urls.get('spor_url', 'Bulunamadı')}")

                    # Değişiklik var mı kontrol et
                    degisiklik_var = False
                    for url_turu in ['content_url', 'spor_url']:
                        if (url_turu in urls and url_turu in mevcut_urls and
                            urls[url_turu] != mevcut_urls[url_turu]):
                            degisiklik_var = True
                            konsol.log(f"[»] {url_turu}: {mevcut_urls[url_turu]} -> {urls[url_turu]}")

                    if degisiklik_var:
                        self._inatbox_guncelle(dosya, mevcut_urls, urls)
                        if self._versiyonu_artir(f"{eklenti_adi}/build.gradle.kts"):
                            konsol.log(f"[+] Versiyon artırıldı")
                    else:
                        konsol.log("[+] URL'ler güncel")

                except Exception as hata:
                    konsol.log(f"[!] Kontrol Edilemedi : {eklenti_adi}")
                    konsol.log(f"[!] {type(hata).__name__} : {hata}")
                    continue
            else:
                try:
                    istek = self.oturum.get(mainurl, allow_redirects=True)
                    konsol.log(f"[+] Kontrol Edildi   : {mainurl}")
                except Exception as hata:
                    konsol.log(f"[!] Kontrol Edilemedi : {mainurl}")
                    konsol.log(f"[!] {type(hata).__name__} : {hata}")
                    continue

                final_url = istek.url[:-1] if istek.url.endswith("/") else istek.url

            if mainurl == final_url:
                continue

            self._mainurl_guncelle(dosya, mainurl, final_url)

            if self._versiyonu_artir(f"{eklenti_adi}/build.gradle.kts"):
                konsol.log(f"[»] {mainurl} -> {final_url}")


if __name__ == "__main__":
    updater = MainUrlUpdater()
    updater.guncelle()
