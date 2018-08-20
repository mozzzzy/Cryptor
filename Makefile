Cryptor.exe: Cryptor.cc
	g++ -DDEBUGCRYPTOR -o Cryptor.exe -I /usr/local/Cellar/openssl/1.0.2k/include -lcrypto  Cryptor.cc

clean:
	rm Cryptor.exe
