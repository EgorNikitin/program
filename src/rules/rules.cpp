//
// Created by root on 12.10.18.
//

#include <fstream>
#include <iostream>
#include <sstream>
#include <vector>
#include <string>

#include <boost/regex.hpp>

#define PROJECT_SOURCE_DIR "/home/univ/CLionProjects/program"

using namespace std;

class Rule {
public:
    string protocol;
    string port;
    string src_ip;
    string dst_ip;
    string payload;

    Rule(const string &protocol, const string &port, const string &src_ip, const string &dst_ip, const string &payload)
            : protocol(protocol), port(port), src_ip(src_ip), dst_ip(dst_ip), payload(payload) {}

    friend ostream &operator<<(ostream &os, const Rule &rule) {
        os << "protocol: " << rule.protocol << " port: " << rule.port << " src_ip: " << rule.src_ip << " dst_ip: "
           << rule.dst_ip << " payload: " << rule.payload;
        return os;
    }
};

std::string tr(const boost::smatch &m) {
    if (m[0].str() == "\\a")
        return std::string(1, '\a');
    if (m[0].str() == "\\b")
        return std::string(1, '\b');
    if (m[0].str() == "\\f")
        return std::string(1, '\f');
    if (m[0].str() == "\\n")
        return std::string(1, '\n');
    if (m[0].str() == "\\r")
        return std::string(1, '\r');
    if (m[0].str() == "\\t")
        return std::string(1, '\t');
    if (m[0].str() == "\\v")
        return std::string(1, '\v');
    if (m[0].str() == "\\\\")
        return std::string(1, '\\');
    if (m[0].str() == "\\'")
        return std::string(1, '\'');
    if (m[0].str() == "\\\"")
        return std::string(1, '\"');
    int num;
    sscanf( m[0].str().c_str(),"\\x%x", &num);
    return std::string(1, (char) num);
}

std::string replaceEscapeCharacters(std::string str) {
    vector<string> escapeCharacters = {
            "\\\\a", "\\\\b", "\\\\f", "\\\\n", "\\\\r",
            "\\\\t", "\\\\v", "\\\\\\\\", "\\\\'", "\\\\\"",
            "\\\\x[0-9a-fA-F]{1,2}"
    };

    std::string regexString = escapeCharacters[0];
    for (uint32_t i = 1; i < escapeCharacters.size(); ++i) {
        regexString += "|" + escapeCharacters[i];
    }

    boost::regex e("(" + regexString + ")");

    return boost::regex_replace(str, e, tr);
}

std::string unquotedString(std::string str) {
    if (str[0] == '\"' && str.back() == '\"') {
        return str.substr(1,str.size()-2);
    }

    if (str[0] == '\"') {
        return str.substr(1,str.size()-1);
    }

    if (str.back() == '\"') {
        str.pop_back();
        return str;
    }

    return str;
}

std::string preparePayloadString(std::string payloadStr) {
    payloadStr = unquotedString(payloadStr);
    payloadStr = replaceEscapeCharacters(payloadStr);
    return payloadStr;
}

vector<string> readFileRules() {
    vector<string> arr;
    ifstream file(PROJECT_SOURCE_DIR"/rules/rules.csv");
    string temp;

    while(getline(file, temp)){
        arr.push_back(temp);
    }

    file.close();
    return arr;
}

template<typename Out>
void split(const std::string &s, char delim, Out result) {
    std::stringstream ss(s);
    std::string item;
    while (std::getline(ss, item, delim)) {
        *(result++) = item;
    }
}
/*
 * this solution does not skip empty tokens,
 * so the following will find 4 items, one of which is empty:
 *
 * std::vector<std::string> x = split("one:two::three", ':');
 */
std::vector<std::string> split(const std::string &s, char delim) {
    std::vector<std::string> elems;
    split(s, delim, std::back_inserter(elems));
    return elems;
}

/*std::vector<std::string> split(const string& input, const string& regex) {
    // passing -1 as the submatch index parameter performs splitting
    std::regex re(regex);
    std::sregex_token_iterator
            first{input.begin(), input.end(), re, -1},
            last;
    return {first, last};
}
std::string replaceAll(std::string str, const std::string& from, const std::string& to) {
    size_t start_pos = 0;
    while((start_pos = str.find(from, start_pos)) != std::string::npos) {
        str.replace(start_pos, from.length(), to);
        start_pos += to.length(); // Handles case where 'to' is a substring of 'from'
    }
    return str;
}

static inline void replaceAll2(std::string &str, const std::string& from, const std::string& to) {
    size_t start_pos = 0;
    while((start_pos = str.find(from, start_pos)) != std::string::npos) {
        str.replace(start_pos, from.length(), to);
        start_pos += to.length(); // Handles case where 'to' is a substring of 'from'
    }
}
*/

