// function to convert int data to hex string
std::string to_hexString(unsigned int val, bool lower = true);

// function to encrypt string using aes
int aesEncrypt(std::string aes_key, std::string plain_string, std::string &encrypted_string);

// function to decrypt string using aes
int aesDecrypt(std::string aes_key, std::string encrypted_string, std::string &decrypted_string);
