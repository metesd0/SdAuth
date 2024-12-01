#ifndef AUTH_HPP
#define AUTH_HPP

#include <string>

std::string getDiskID();

bool validateAuthKey(const std::string& authKey, const std::string& diskID);


void setTextColor(bool isValidKey, bool isExpired);


void authenticate(const std::string& authKey);

#endif
