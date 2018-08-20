#include <iostream>
#include <openssl/aes.h>
#include <openssl/evp.h>

// int -> hex string
std::string to_hexString(unsigned int val, bool lower = true) {
    if( !val )
        return std::string("0");
    std::string str;
    const char hc = lower ? 'a' : 'A';     // 小文字 or 大文字表記
    while( val != 0 ) {
        int d = val & 15;     // 16進数一桁を取得
        if( d < 10 )
            str.insert(str.begin(), d + '0');  //  10未満の場合
        else //  10以上の場合
            str.insert(str.begin(), d - 10 + hc);
        val >>= 4;
    }
    return str;
}





int aesEncrypt(std::string aes_key, std::string plain_string, std::string &encrypted_string) {

	encrypted_string = "";

	// key length should be equal EVP_CIPHER_key_length(EVP_aes_128_ecb())	
	if(aes_key.length() != EVP_CIPHER_key_length(EVP_aes_128_ecb())) {
		return 1;
	}

	// init
	EVP_CIPHER_CTX en;
	EVP_CIPHER_CTX_init(&en);
	EVP_EncryptInit_ex(&en, EVP_aes_128_ecb(), NULL, (unsigned char *)aes_key.c_str(), NULL);

	// plain_string_length
	int plain_string_length = plain_string.length();
	// 
	int c_len = plain_string_length + EVP_MAX_BLOCK_LENGTH;
	// 
	unsigned char *ciphertext;
	//
	ciphertext = (unsigned char *) calloc(c_len, sizeof(char));

	//
	EVP_EncryptUpdate(&en, (unsigned char *)ciphertext, &c_len, (unsigned char *)plain_string.c_str(), plain_string_length);
	//
	int f_len;
	EVP_EncryptFinal_ex(&en, (unsigned char *)(ciphertext + c_len), &f_len);

	int i;
    for(i=0;i<c_len+f_len;i++){

		// 16 進数 で最低 2 桁. 満たないものは 0を付与
		int dec = ciphertext[i];
		std::string hex_str = to_hexString(dec);
		if(hex_str.length() < 2){
			int zc;
			for(zc = 0; zc < (2 - hex_str.length()); zc ++ ){
				hex_str = "0" + hex_str;
			}
		}

		encrypted_string += hex_str;
    }

    free(ciphertext);

    EVP_CIPHER_CTX_cleanup(&en);	

	return 0;
}


int aesDecrypt(std::string aes_key, std::string encrypted_string, std::string &decrypted_string) {

	decrypted_string = "";

	// key length should be equal EVP_CIPHER_key_length(EVP_aes_128_ecb())
	if(aes_key.length() != EVP_CIPHER_key_length(EVP_aes_128_ecb())) {
		return 1;
	}

	// init
	EVP_CIPHER_CTX  de;
	EVP_CIPHER_CTX_init(&de);
	EVP_DecryptInit_ex(&de, EVP_aes_128_ecb(), NULL, (unsigned char *)aes_key.c_str(), NULL);

	// aes_key.length() % 2 should be equals 0
	if(aes_key.length() % 2 != 0) {
		return 1;
	}

	// convert encrypted string to encrypted c str
	int hc = 0;	// hex counter
	char *encrypted_c_str = (char *) malloc(encrypted_string.length());
	for(hc = 0; hc < encrypted_string.length(); hc += 2) {
		encrypted_c_str[hc/2] = strtol(encrypted_string.substr(hc, 2).c_str(), NULL, 16);
	}

	int encrypted_data_size = hc/2;
	// allocates memory, size is (encrypted_data_size+1) * sizeof(char)
	char *plaintext = (char *) calloc(encrypted_data_size+1, sizeof(char));

	EVP_DecryptUpdate(&de, (unsigned char *)plaintext, &encrypted_data_size, (unsigned char *)encrypted_c_str, encrypted_data_size);

	int f_len = 0;	
	EVP_DecryptFinal_ex(&de, (unsigned char *)(plaintext + encrypted_data_size), &f_len);
	
	plaintext[encrypted_data_size + f_len] = '\0';

	decrypted_string = plaintext;

	EVP_CIPHER_CTX_cleanup(&de);

	free(plaintext);
	free(encrypted_c_str);

	return 0;
}


#ifdef DEBUGCRYPTOR
int main(){
	std::string enc = "";
	int result = aesEncrypt("aaaaaaaaaaaaaaaa", "this is test clean text.", enc);
	std::cout << "result = " << result << std::endl;
	std::cout << "enc = " << enc << std::endl;

	std::string dec = "";
	result = aesDecrypt("aaaaaaaaaaaaaaaa", enc, dec);
	std::cout << "result = " << result << std::endl;
	std::cout << "dec = " << dec << std::endl;

	return 0;
}
#endif
