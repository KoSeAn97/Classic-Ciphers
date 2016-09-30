#include <iostream>
#include <list>
#include <algorithm>
#include <codecvt>

#include "ciphers.hpp"
#include "utf8.h"

#define ALPH_ENG 26
#define ALPH_RUS 32
#define SPACE_WC L' '
#define LEAST_FR L'X'
#define MX_S_ENG 5
#define MX_S_RUS 6

extern std::locale loc;

//std::wstring_convert< std::codecvt_utf8<wchar_t> > converter;

class utf_wrapper {
public:
    std::wstring from_bytes(const std::string & str);
    std::string to_bytes(const std::wstring & wstr);
} converter;

std::wstring utf_wrapper::from_bytes(const std::string & str) {
    std::wstring utf16line;
    utf8::utf8to16(str.begin(), str.end(), std::back_inserter(utf16line));
    return utf16line;
}

std::string utf_wrapper::to_bytes(const std::wstring & wstr) {
    std::string utf8line;
    utf8::utf16to8(wstr.begin(), wstr.end(), std::back_inserter(utf8line));
    return utf8line;
}

wchar_t pfront(std::wstring & str);
void create_Polybius_Square(std::vector< std::vector<wchar_t> > & matrix, std::wstring r_key, bool is_english);
coords find_letter(const std::vector< std::vector<wchar_t> > & table, wchar_t ch);
void touppers(std::wstring & s);

Caesar::Caesar(int init_shift) : shift(init_shift) {}
void Caesar::backdoor() {}
wchar_t Caesar::shifter(bool is_enc, wchar_t ch) const {
    wchar_t base;
    int mod;
    if(ch < 0xFF) {
        mod = ALPH_ENG;
        if(isupper(ch, loc)) base = L'A';
        else base = L'a';
    } else {
        mod = ALPH_RUS;
        if(isupper(ch, loc)) base = L'А';
        else base = L'а';
    }
    if(is_enc) return base + (ch - base + shift + mod) % mod;
    else return base + (ch - base - shift + mod) % mod;
}
std::string Caesar::encrypt(const std::string & plaintext) {
    std::wstring buffer = converter.from_bytes(plaintext);
    std::transform(
        buffer.begin(),
        buffer.end(),
        buffer.begin(),
        [this](wchar_t ch) {
            backdoor();
            if(!isalpha(ch, loc)) return ch;
            return shifter(true, ch);
        }
    );
    return converter.to_bytes(buffer);
}
std::string Caesar::decrypt(const std::string & ciphertext) {
    std::wstring buffer = converter.from_bytes(ciphertext);
    std::transform(
        buffer.begin(),
        buffer.end(),
        buffer.begin(),
        [this](wchar_t ch) {
            backdoor();
            if(!isalpha(ch, loc)) return ch;
            return shifter(false, ch);
        }
    );
    return converter.to_bytes(buffer);
}

Vigenere::Vigenere(const std::string & key) {
    std::wstring buffer = converter.from_bytes(key);
    wchar_t base;
    for(auto it = buffer.begin(); it != buffer.end(); ++it) {
        if(!isalpha(*it, loc)) {
            base = L' ';
        } else if(*it < 0xFF) {
            if(isupper(*it, loc)) base = L'A';
            else base = L'a';
        } else {
            if(isupper(*it, loc)) base = L'А';
            else base = L'а';
        }
        shifts.push_back(*it - base);
    }
    key_len = shifts.size();
}
void Vigenere::backdoor() {
    shift = shifts[counter];
    counter = (counter + 1) % key_len;
}
std::string Vigenere::encrypt(const std::string & plaintext) {
    counter = 0;
    return Caesar::encrypt(plaintext);
}
std::string Vigenere::decrypt(const std::string & ciphertext) {
    counter = 0;
    return Caesar::decrypt(ciphertext);
}

Transposition::Transposition(const std::vector<int> & init_perm) {
    key_len = init_perm.size();
    for(int i = 0; i < key_len; i++) direct_perm[init_perm[i] - 1] = i;
    for(int i = 0; i < key_len; i++) inverse_perm[direct_perm[i]] = i;
}
std::string Transposition::encrypt(const std::string & plaintext) {
    std::vector< std::list<wchar_t> > table(key_len);
    std::wstring buffer = converter.from_bytes(plaintext);

    int l_height = buffer.size() / key_len + (buffer.size() % key_len ? 1 : 0);
    int msg_len = l_height * key_len;

    // do padding
    buffer.resize(msg_len, SPACE_WC);

    // fill the table
    for(int i = 0; i < msg_len; i++) {
        table[i % key_len].push_back(buffer[i]);
    }

    // construct ciphertext
    int index;
    buffer.clear();
    for(int i = 0; i < key_len; i++) {
        index = direct_perm.at(i);
        buffer.append(table[index].begin(), table[index].end());
    }

    return converter.to_bytes(buffer);
}
std::string Transposition::decrypt(const std::string & ciphertext) {
    std::vector< std::list<wchar_t> > table(key_len);
    std::wstring buffer = converter.from_bytes(ciphertext);

    int l_height = buffer.size() / key_len + (buffer.size() % key_len ? 1 : 0);
    int msg_len = l_height * key_len;

    // fill the table
    for(int i = 0; i < msg_len; i++) {
        table[i / l_height].push_back(buffer[i]);
    }

    // construct plaintext
    int index;
    buffer.clear();
    for(int i = 0; i < msg_len; i++) {
        index = inverse_perm.at(i % key_len);
        buffer.append(1, table[index].front());
        table[index].pop_front();
    }

    return converter.to_bytes(buffer);
}

Polybius::Polybius(bool is_english, int mode) {
    cipher_mode = mode;
    create_Polybius_Square(matrix, std::wstring(), is_english);
    dim_m = matrix.size();
}
void Polybius::mode_1(std::wstring & src, std::string & dst, bool is_enc) {
    int shift = is_enc ? 1 : -1;
    std::transform(
        src.begin(),
        src.end(),
        src.begin(),
        [shift, this](wchar_t ch) {
            if(!isalpha(ch, loc)) return ch;
            coords p = find_letter(matrix, ch);
            int sh = (p.first + shift + dim_m) % dim_m;
            while(!isalpha(matrix[sh][p.second], loc))
                sh = (sh + shift + dim_m) % dim_m;
            return matrix[sh][p.second];
        }
    );
    dst = converter.to_bytes(src);
}
void Polybius::enc_2(std::wstring & plaintext, std::string & ciphertext) {
    std::vector<int> first, second;
    coords p;
    for(auto ch: plaintext) {
        if(!isalpha(ch, loc)) continue;
        p = find_letter(matrix, ch);
        second.push_back(p.first);
        first.push_back(p.second);
    }
    int lenght = first.size();
    bool odd = lenght % 2;

    std::wstring buffer;
    for(int i = 0; i + 1 < lenght; i += 2)
        buffer.append(1, matrix[first[i+1]][first[i]]);
    if(odd)
        buffer.append(1, matrix[second[0]][first[lenght-1]]);
    for(int i = odd; i + 1 < lenght; i += 2)
        buffer.append(1, matrix[second[i+1]][second[i]]);

    ciphertext = converter.to_bytes(buffer);
}
void Polybius::dec_2(std::wstring & ciphertext, std::string & plaintext) {
    std::vector<int> foo;
    coords p;
    for(auto ch: ciphertext) {
        if(!isalpha(ch, loc)) continue;
        p = find_letter(matrix, ch);
        foo.push_back(p.second);
        foo.push_back(p.first);
    }
    int half_lenght = foo.size() / 2;
    std::wstring buffer;
    for(int i = 0; i < half_lenght; i++)
        buffer.append(1, matrix[foo[half_lenght + i]][foo[i]]);

    plaintext = converter.to_bytes(buffer);
}
std::string Polybius::encrypt(const std::string & plaintext) {
    std::wstring buffer = converter.from_bytes(plaintext);
    touppers(buffer);
    std::replace(buffer.begin(), buffer.end(), L'J', L'I');
    std::string ciphertext;

    if(cipher_mode % 2) mode_1(buffer, ciphertext, true);
    else enc_2(buffer, ciphertext);

    return ciphertext;
}
std::string Polybius::decrypt(const std::string & ciphertext) {
    std::wstring buffer = converter.from_bytes(ciphertext);
    touppers(buffer);
    std::replace(buffer.begin(), buffer.end(), L'J', L'I');
    std::string plaintext;

    if(cipher_mode % 2) mode_1(buffer, plaintext, false);
    else dec_2(buffer, plaintext);

    return plaintext;
}

Playfair::Playfair(const std::string & key) {
    std::wstring reduced_key = reduce(key);
    create_Polybius_Square(matrix, reduced_key, true);
    dim_m = matrix.size();
}
std::wstring Playfair::reduce(const std::string & key) const {
    std::wstring buffer = converter.from_bytes(key);
    touppers(buffer);
    std::replace(buffer.begin(), buffer.end(), L'J', L'I');

    std::wstring reduced_key;
    for(auto ch: buffer) {
        if(reduced_key.find(ch) == std::string::npos)
            reduced_key.append(1, ch);
    }

    return reduced_key;
}
std::ostream & operator << (std::ostream & stream, std::pair<wchar_t, wchar_t> elem) {
    return stream << "(" << (char) elem.first << ", " << (char) elem.second << ")";
}
std::ostream & operator << (std::ostream & stream, std::pair<int, int> elem) {
    return stream << "{" << elem.first << ", " << elem.second << "}";
}
void Playfair::perform(Playfair::digram & dg) const {
    coords a = find_letter(matrix, dg.first);
    coords b = find_letter(matrix, dg.second);

    // lazy evaluation
    a == b || rule_2(dg, a, b) || rule_3(dg, a, b) || rule_4(dg, a, b);
}
wchar_t Playfair::rule_1(Playfair::digram & dg) const {
    if(dg.first != dg.second) return 0;
    if(dg.first == LEAST_FR) return 0;

    wchar_t buffer = dg.second;
    dg = digram(dg.first, LEAST_FR);
    return buffer;
}
bool Playfair::rule_2(Playfair::digram & dg, const coords & a, const coords & b) const {
    if(a.first != b.first)
        return false;

    int shift = state_encrypt ? 1 : -1;
    int row = a.first;
    dg = digram(
        matrix[row][(a.second + shift + dim_m) % dim_m],
        matrix[row][(b.second + shift + dim_m) % dim_m]
    );
    return true;
}
bool Playfair::rule_3(Playfair::digram & dg, const coords & a, const coords & b) const {
    if(a.second != b.second)
        return false;

    int shift = state_encrypt ? 1 : -1;
    int column = a.second;
    dg = digram(
        matrix[(a.first + shift + dim_m) % dim_m][column],
        matrix[(b.first + shift + dim_m) % dim_m][column]
    );
    return true;
}
bool Playfair::rule_4(Playfair::digram & dg, const coords & a, const coords & b) const {
    dg = digram(
        matrix[a.first][b.second],
        matrix[b.first][a.second]
    );
    return true;
}
std::string Playfair::encrypt(const std::string & plaintext) {
    state_encrypt = true;
    std::wstring buffer = converter.from_bytes(plaintext);
    touppers(buffer);
    std::replace(buffer.begin(), buffer.end(), L'J', L'I');
    std::wstring ciphertext;

    digram current_digram;
    wchar_t reminder = 0;
    while(!buffer.empty() || reminder) {
        // get first
        if(reminder) {
            current_digram.first = reminder;
            reminder = 0;
        } else {
            while(!buffer.empty() && !isalpha(buffer.front(), loc))
                ciphertext.append(1, pfront(buffer));
            if(buffer.empty()) break;
            current_digram.first = pfront(buffer);
        }
        // get second
        if(buffer.empty() || !isalpha(buffer.front(), loc))
            current_digram.second = LEAST_FR;
        else
            current_digram.second = pfront(buffer);

        reminder = rule_1(current_digram);
        perform(current_digram);
        ciphertext.append(1, current_digram.first);
        ciphertext.append(1, current_digram.second);
    }
    return converter.to_bytes(ciphertext);
}
std::string Playfair::decrypt(const std::string & ciphertext) {
    state_encrypt = false;

    std::wstring buffer = converter.from_bytes(ciphertext);
    touppers(buffer);
    std::wstring plaintext;

    digram current_digram;
    while(!buffer.empty()) {
        // get first
        while(!buffer.empty() && !isalpha(buffer.front(), loc))
            plaintext.append(1, pfront(buffer));
        if(buffer.empty()) break;
        current_digram.first = pfront(buffer);
        // get second
        current_digram.second = pfront(buffer);

        perform(current_digram);
        plaintext.append(1, current_digram.first);
        plaintext.append(1, current_digram.second);
    }

    return converter.to_bytes(plaintext);
}

void touppers(std::wstring & s) {
    std::transform(
        s.begin(),
        s.end(),
        s.begin(),
        [](wchar_t ch) {
            return toupper(ch, loc);
        }
    );
}
wchar_t pfront(std::wstring & str) {
    wchar_t buffer = str.front();
    str.erase(0,1);
    return buffer;
}
void create_Polybius_Square(std::vector< std::vector<wchar_t> > & matrix, std::wstring r_key, bool is_english) {
    int matrix_dim, matrix_size, alph_len;
    wchar_t letter;

    // determine matrix's properties
    matrix_dim = is_english ? MX_S_ENG : MX_S_RUS;
    matrix_size = matrix_dim * matrix_dim;
    alph_len = is_english ? ALPH_ENG : ALPH_RUS;
    letter = is_english ? L'A' : L'А';

    // set matrix's size
    matrix.resize(matrix_dim);
    for(auto & t: matrix) t.resize(matrix_dim);

    // input the key to the matrix
    int key_len = r_key.size();
    for(int i = 0; i < key_len; i++)
        matrix[i / matrix_dim][i % matrix_dim] = r_key[i];

    // if language is english then drop out letter 'J'
    if(is_english) {
        r_key.append(1, 'J');
        alph_len--;
    }

    // fill remaining letters to the table
    for(int i = key_len; i < alph_len; i++) {
        while(r_key.find(letter) != std::string::npos) letter++;
        matrix[i / matrix_dim][i % matrix_dim] = letter++;
    }

    // fill the void
    for(int i = alph_len; i < matrix_size; i++)
        matrix[i / matrix_dim][i % matrix_size] = SPACE_WC;
}
coords find_letter(const std::vector< std::vector<wchar_t> > & table, wchar_t ch) {
    int x = -1, y = -1;

    for(int i = 0; i < table.size(); i++)
        for(int j = 0; j < table[i].size(); j++)
            if(table[i][j] == ch) {
                x = i;
                y = j;
                break;
            }

    return coords(x, y);
}
