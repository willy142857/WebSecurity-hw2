#include <exception>
#include <string>

#include "utility.h"

class SSLException : public std::exception
{
public:
    SSLException(const char* s = "")
        :str(s) 
        {
            using namespace std::string_literals;
            str = str + "\n"s + getOpenSSLError();
        }

    virtual const char* what() const throw()
    {   
        return str.c_str();
    }

private:
    std::string str;
};