#ifndef AUTH_HPP
#define AUTH_HPP

#include <string>

// Disk ID'sini alacak fonksiyon
std::string getDiskID();

// Key doğrulaması yapacak fonksiyon
bool validateAuthKey(const std::string& authKey, const std::string& diskID);

// Renk ayarlarını yapacak fonksiyon
void setTextColor(bool isValidKey, bool isExpired);

// Sunucuya bağlanacak ve doğrulama işlemini yapacak ana fonksiyon
void authenticate(const std::string& authKey);

#endif // AUTH_HPP
