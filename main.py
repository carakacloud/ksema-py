from ksema import Ksema

# user = Ksema("Ksema-32.caraka.cloud", "wzkGGHq+McvlkjxaLH97hgOFF+SxYyqrgOiXY3EqGLLkM0KQcCbGmbMWNC/YZd19MNv4w8/dsCGcboTK", "123456")
user = Ksema("Ksema-32.caraka.cloud", "EF+y1KewWAsbPAtRebb8v1XkJK+E5yJdMUbYdT5hHxSpgjgjiS9xqxJHoXS1PtDxQsdHrhIAmIzahg4Q", "123456")
# user = Ksema("Ksema-32.caraka.cloud", "krSoZKQcI5SvEFpRlK06JxnRd9ZpSaHETh41nkT087E5STCgTc8mkkJtPP3pmFqJaEYpiv+ZKDNGd2FL", "12345678")

# print(user.keygen("PUB01", "PRIV01"))

# cipher = user.encrypt(b"test enc", "AES01")

# print(user.decrypt(cipher, "AES01"))

# print(user.delete("AES01"))

signature = user.sign(b"test sign", "PRIV01")

print(user.verify(b"test sign", signature, "PUB01"))

# random = user.rng()
# print(random)
# print(len(random))

# print(user.backup("testcontra.key", "PRIV01"))