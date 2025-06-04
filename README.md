# KSEMA

Ksema adalah layanan Managed Hardware Security Module (HSM) yang berjalan di atas infrastruktur cloud Equnix yang profesional dan diandalkan banyak perusahaan. Dengan Ksema, Anda mampu menjalankan operasi kriptografi dengan infrastruktur bersertifikasi FIPS 140-2 Level 3 tanpa repot mengelola hardware fisik sendiri.

Minimum Python Version: **3.12.3**

## Installation
```bash
pip install git+https://github.com/carakacloud/ksema-py.git
```

## Usage
```py
import os
from ksema import Ksema

func main() {
	ksemaServerIp := os.getenv("KSEMA_HOST")
	ksemaAPIKey := os.getenv("KSEMA_API_KEY")
	ksemaPIN := os.getenv("KSEMA_PIN")

	user = Ksema(ksemaServerIp, ksemaAPIKey, ksemaPIN)

	try:
        if not user.ping():
            sys.exit("Failed to ping server (returned False)")
    except Exception as e:
        sys.exit(f"Failed to ping server (exception: {e})")

	message = b"Hello, this is a secret message!"

    try:
    	encrypted = user.encrypt(message, "")
    except Exception as e:
		print("Failed to encrypt")

	print(f"Encrypted: {encrypted}")

    try:
    	decrypted = user.decrypt(encrypted, "")
    except Exception as e:
		print("Failed to decrypt")

	print(f"Decrypted: {decrypted.decode()}")
}
```