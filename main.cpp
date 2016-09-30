#include <locale>
#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <algorithm>
#include <limits>

#ifdef OS_WINDOWS
    #include <tr1/memory>
    using std::tr1::shared_ptr;
#else
    #include <memory>
    using std::shared_ptr;
#endif

#include "ciphers.hpp"

using std::cout;
using std::cerr;
using std::cerr;
using std::endl;

using std::vector;
using std::string;
using std::stringstream;

using std::getline;

using std::numeric_limits;

std::locale loc;

// Very weak implementation of Russian сtype facet
class russian_ctype : public std::ctype<wchar_t> {
 protected:
    bool do_is(mask m, char_type c) const;
    char_type do_toupper(char_type c) const;
};
bool russian_ctype::do_is(mask m, char_type c) const {
    if (c >= L'А' && c <= L'Я') {
        if ((m & alpha))
            return true;
        if ((m & upper))
            return true;
    }
    if (c >= L'а' && c <= L'я') {
        if ((m & alpha))
            return true;
        if ((m & upper))
            return true;
    }
    return ctype::do_is(m, c);
}
russian_ctype::char_type russian_ctype::do_toupper(char_type c) const {
    if (c >= L'а' && c <= L'я')
        return c + L'Ю' - L'ю';
    return ctype::do_toupper(c);
}

//http://stackoverflow.com/questions/2159452/c-assign-cin-to-an-ifstream-variable
/*
The noop is to specify a deleter that does nothing in the cin case, well,
cin is not meant to be deleted
*/
struct noop {
    void operator() (...) {}
};

void print_help(const char * argv0) {
    const char * usage =
R"(where CIPHER is from list:
--caesar
    first   line: key-integer
    second  line: text
--transposition
    first   line: key-permutation i_1,...,i_n separated by commas
                  started with 1
    second  line: text
--polybius
    first   line: LANG VARIANT
    second  line: text
    (where LANG = russian || english, VARIANT = 1 || 2)
--vigenere
    first   line: key-string
    second  line: text-string
--playfair
    first   line: key-string
    second  line: text-string
and MODE is from list:
--encrypt
--decrypt
)";
    cout << "Usage: " << argv0 << " CIPHER MODE " << "[<input_text_path> = stdin]" << endl;
    cout << usage;
}

void check_argc(int argc, int from, int to=numeric_limits<int>::max()) {
    if(argc < from)
        throw string("too few arguments for operation");

    if(argc > to)
        throw string("too many arguments for operation");
}

//https://www.safaribooksonline.com/library/view/c-cookbook/0596007612/ch04s07.html
vector<string> split(const string & s, char ch) {
    vector<string> v;

    string::size_type i = 0;
    string::size_type j = s.find(ch);
    while(j != string::npos) {
        v.push_back(s.substr(i, j-i));
        i = ++j;
        j = s.find(ch, j);

        if(j == string::npos)
            v.push_back(s.substr(i, s.size()-i));
    }
    return v;
}

template<typename ValueType>
ValueType read_value(string s) {
    stringstream ss(s);
    ValueType res;
    ss >> res;
    if (ss.fail() or not ss.eof())
        throw string("bad argument: ") + s;
    return res;
}

bool check_permutation(vector<int> perm) {
    std::sort(
        perm.begin(),
        perm.end()
    );

    int counter = 0;
    bool result = std::all_of(
        perm.begin(),
        perm.end(),
        [& counter](int x) {
            return ++counter == x;
        }
    );

    return result;
}

vector<int> get_permutation(const string & s) {
    vector<string> strperm = split(s, ',');
    vector<int> tmp;
    for(auto num: strperm)
        tmp.push_back(read_value<int>(num));
    return tmp;
}

int main(int argc, char ** argv) {
    try {
        loc = std::locale(
            std::locale::classic(),
            new russian_ctype
        );
    } catch(...) {
        cerr << "THE PROGRAM WORKS IN ENGLISH ONLY MODE" << endl;
    }
    try {
        std::locale::global(loc);

        check_argc(argc, 2);
        if(string(argv[1]) == "--help") {
            print_help(argv[0]);
            return 0;
        }

        check_argc(argc, 3, 4);
        string cipher(argv[1]);
        string mode(argv[2]);

        shared_ptr<std::istream> input;
        if(3 == argc)
            input.reset(&std::cin, noop());
        else
            input.reset(new std::ifstream(argv[3]));

        if(input->fail())
            throw string("unable to open file - ") + string(argv[3]);

        std::unique_ptr<BaseCipher> algorithm = nullptr;
        if(cipher == "--caesar") {
            string str;
            getline(*input, str);

            int shift = read_value<int>(str);
            algorithm.reset(
                new Caesar(shift)
            );
        } else if(cipher == "--vigenere") {
            string str;
            getline(*input, str);

            string key = read_value<string>(str);
            algorithm.reset(
                new Vigenere(key)
            );
        } else if(cipher == "--playfair") {
            string str;
            getline(*input, str);

            string key = read_value<string>(str);
            algorithm.reset(
                new Playfair(key)
            );
        } else if(cipher == "--transposition") {
            string key;
            getline(*input, key);

            vector<int> perm = get_permutation(key);
            if(!check_permutation(perm))
                throw string("Not a permutation");
            if(perm.empty())
                throw string("Empty permutation");\

            algorithm.reset(
                new Transposition(perm)
            );
        } else if(cipher == "--polybius") {
            string str;
            getline(*input, str);
            vector<string> params = split(str, ' ');
            if(params.size() != 2)
                throw string("too few parameters");

            string language = read_value<string>(params[0]);
            int mode = read_value<int>(params[1]);

            bool is_english;
            if(language == "russian") {
                is_english = false;
            } else if(language == "english") {
                is_english = true;
            } else {
                throw string("unknown language - ") + language;
            }
            if(mode > 2 || mode < 1)
                throw string("unknown mode");
            if(mode == 2 && !is_english)
                throw string("russian with mode 2 is forbidden");

            algorithm.reset(
                new Polybius(is_english, mode)
            );
        } else {
            throw string("unknown cipher - ") + cipher;
        }

        bool is_enc;
        if(mode == "--encrypt") {
            is_enc = true;
        } else if(mode == "--decrypt") {
            is_enc = false;
        } else {
            throw string("unknown mode - ") + mode;
        }

        string given_text;
        getline(*input, given_text);

        cout << " input: \"" << given_text << "\"" << endl;
        cout << "output: \"";
        if(is_enc)
            cout << algorithm->encrypt(given_text);
        else
            cout << algorithm->decrypt(given_text);
        cout << "\"" << endl;

    } catch(const string & s) {
        cerr << "Error: " << s << endl;
        cerr << "For help type: " << endl << argv[0] << " --help" << endl;
        return 1;
    }
    
    return 0;
}
