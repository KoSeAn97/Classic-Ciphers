#include <string>
#include <vector>
#include <map>

#ifndef __CIPHERS__
#define __CIPHERS__

using coords = std::pair<int, int>;

class BaseCipher {
public:
    virtual ~BaseCipher() {};
    virtual std::string encrypt(const std::string & plaintext) = 0;
    virtual std::string decrypt(const std::string & ciphertext) = 0;
};

class Caesar: public BaseCipher {
 protected:
    int shift;
    wchar_t shifter(bool is_enc, wchar_t ch) const;
    virtual void backdoor();
 public:
    Caesar(int init_shift = 3);

    std::string encrypt(const std::string & plaintext) override;
    std::string decrypt(const std::string & ciphertext) override;
};

class Vigenere: public Caesar {
    int counter, key_len;
    std::vector<int> shifts;

    void backdoor() override;
 public:
    Vigenere(const std::string & key);

    std::string encrypt(const std::string & plaintext) override;
    std::string decrypt(const std::string & ciphertext) override;
};

class Transposition: public BaseCipher {
    int key_len;
    std::map<int, int> direct_perm;
    std::map<int, int> inverse_perm;
 public:
    Transposition(const std::vector<int> & init_perm);

    std::string encrypt(const std::string & plaintext) override;
    std::string decrypt(const std::string & ciphertext) override;
};

class Polybius: public BaseCipher {
    std::vector< std::vector<wchar_t> > matrix;
    int dim_m;
    int cipher_mode;

    void mode_1(std::wstring & src, std::string & dst, bool is_enc);
    void enc_2(std::wstring & plaintext, std::string & ciphertext);
    void dec_2(std::wstring & ciphertext, std::string & plaintext);
 public:
    Polybius(bool is_english, int mode);

    std::string encrypt(const std::string & plaintext) override;
    std::string decrypt(const std::string & ciphertext) override;
};

class Playfair: public BaseCipher {
    using digram = std::pair<wchar_t, wchar_t>;

    std::vector< std::vector<wchar_t> > matrix;
    bool state_encrypt;
    int dim_m;

    std::wstring reduce(const std::string & key) const;

    void    perform(digram & dg) const;
    wchar_t rule_1(digram & dg) const;
    bool    rule_2(digram & dg, const coords & a, const coords & b) const;
    bool    rule_3(digram & dg, const coords & a, const coords & b) const;
    bool    rule_4(digram & dg, const coords & a, const coords & b) const;
 public:
    Playfair(const std::string & key);

    std::string encrypt(const std::string & plaintext) override;
    std::string decrypt(const std::string & ciphertext) override;
};

#endif
