# TLS test fixtures

Bu dizindeki sertifikalar ve private key yalnız geçici `127.0.0.1` TLS test
sunucuları içindir; production kimlik bilgisi değildir ve başka bir sistemde
kullanılmaz. Fixture'lar `src` dışında tutulduğu için backend TypeScript build
çıktısına kopyalanmaz.

- `localhost-valid-cert.pem`: `localhost` ve `127.0.0.1`, 2025–2035
- `mismatch-valid-cert.pem`: yalnız `fixture.invalid`, 2025–2035
- `localhost-expired-cert.pem`: `localhost` ve `127.0.0.1`, 2020–2021
- `test-key.pem`: yalnız yukarıdaki test sertifikalarıyla eşleşen test anahtarı
