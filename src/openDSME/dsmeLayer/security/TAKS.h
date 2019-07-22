/*
 * openDSME-secure extension
 *
 * Implementation of the security features of the IEEE 802.15.4 with the
 * Topology-Authenticated Key Scheme (TAKS)
 *
 * Authors: Walter Tiberti <walter.tiberti@graduate.univaq.it
 *
 * Based on
 *          openDSME
 *
 * Copyright (c) 2019, University of L'Aquila (Italy) and CISTER Centre (Portugal)
 *
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright owners nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT OWNERS AND CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNERS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef IEEE802154eDSME_TAKS_H_
#define IEEE802154eDSME_TAKS_H_

#include <stdlib.h>
#include <string>
#include <random>
#include <array>

namespace dsme {

/* Key and MAC length to Default if undefined */
#ifndef TAKS_KEY_LEN
    #define TAKS_KEY_LEN 16 // 128 bits
#endif
#ifndef TAKS_MAC_LEN
    #define TAKS_MAC_LEN 16 // 128 bits
#endif
#define RIJNDAEL_POLY 0x11B

template<size_t COMPLEN>
class TaksKeyComponent {
public:
    TaksKeyComponent() {
        for (int i = 0; i < COMPLEN; ++i) {
            data[i] = 0x00;
        }
    }

    TaksKeyComponent(const TaksKeyComponent<COMPLEN>& src) {
        for (int i = 0; i < COMPLEN; ++i) {
            getX()[i] = src.getX()[i];
            getY()[i] = src.getY()[i];
        }
    }

    void fill(uint8_t value) {
        for (int i = 0; i < COMPLEN; ++i)
            data[i] = value;
    }

    TaksKeyComponent(const std::string &s) {
        fromHexString(s);
    }

    int fromHexString(const std::string &s) {
        int i;
        if (s.size() & 1)
            return -1;
        for (i = 0; i < COMPLEN; ++i) {
            std::string t = s.substr(2*i, 2);
            uint8_t value = (uint8_t) strtoul(t.c_str(), nullptr, 16);
            data[i] = value;
        }
        return i;
    }

    std::string toHexString() const {
        std::string t;
        for (int i = 0; i < COMPLEN; ++i) {
            char buf[3];
            buf[2] = '\0';
            snprintf(buf, 3, "%02x", data[i]);
            t += buf;
        }
        return t;
    }

    uint8_t *getX() {
        return data;
    }

    uint8_t *getY() {
        return data+(COMPLEN/2);
    }

    const uint8_t *getX() const {
        return data;
    }

    const uint8_t *getY() const {
        return data+(COMPLEN/2);
    }

protected:
    uint8_t data[COMPLEN];
};

template<size_t KEYLEN, uint16_t POLY, size_t MACLEN>
class Taks {
public:
    static int Encrypt(uint8_t *out_ciphertext, size_t max_ciphertext,
                       uint8_t *plaintext, size_t size,
                       std::array<uint8_t, MACLEN> &out_mac,
                       TaksKeyComponent<KEYLEN*2> &out_kri,
                       const TaksKeyComponent<KEYLEN*2> &src_LKC,
                       const TaksKeyComponent<KEYLEN*2> &dst_TKC,
                       const TaksKeyComponent<KEYLEN*2> &dst_TV
                       ) {

        TaksKeyComponent<KEYLEN> ss;
        TaksKeyComponent<KEYLEN*2> nonce;
        TaksKeyComponent<KEYLEN*2> alpha_LKC;

        // 1. retrieve a nonce
        getNonce(nonce);

        // 2. obtain alpha*LKC
        elementwise_mult(alpha_LKC, nonce, src_LKC);

        // 3. obtain the SS
        tak(ss, alpha_LKC, dst_TV);

        // 4. obtain the KRI
        elementwise_mult(out_kri, nonce, dst_TKC);

        // 5. Symmetric Encryption
        // TODO - for now, just xor against the key
        size_t minsize = (size < max_ciphertext)? size : max_ciphertext;
        simple_xor_cipher(out_ciphertext, plaintext, minsize, ss.getX());

        // 6. Compute MAC
        // TODO - for now, just a 32 bit checksum repeated and xored with the ss
        simple_checksum_mac(out_mac, out_ciphertext, minsize, ss.getX());

        // erase the nonce (for security)
        for (int i = 0; i < KEYLEN; ++i) {
            nonce.getX()[i] = nonce.getY()[i] = 0;
            ss.getX()[i] = 0;
        }
        return 0;
    }

    static int Decrypt(uint8_t *out_plaintext, size_t max_plaintext,
                       uint8_t *ciphertext, size_t size,
                       std::array<uint8_t, MACLEN> &mac,
                       TaksKeyComponent<KEYLEN*2> &kri,
                       const TaksKeyComponent<KEYLEN*2> &LKC
                       )
    {
        // 1. Reconstruct the key
        TaksKeyComponent<KEYLEN> ss;
        std::array<uint8_t, MACLEN> computed_mac;

        tak(ss, kri, LKC);

        // 2. Check the MAC
        // TODO
        simple_checksum_mac(computed_mac, ciphertext, size, ss.getX());
        for (int i = 0; i < MACLEN; ++i) {
            if (computed_mac[i] != mac[i])
                return -1;
        }
        // 2. Decrypt the message
        // TODO
        size_t minsize = (size < max_plaintext)? size : max_plaintext;
        simple_xor_cipher(out_plaintext, ciphertext, minsize, ss.getX());
        return 0;
    }
private:
    //Taks(); // private constructor!
    /*
    static Taks<TAKS_KEY_LEN, RIJNDAEL_POLY, TAKS_MAC_LEN> TaksScheme;

    static Taks<TAKS_KEY_LEN, RIJNDAEL_POLY, TAKS_MAC_LEN>& getInstance() {
        return Taks<TAKS_KEY_LEN, RIJNDAEL_POLY, TAKS_MAC_LEN>::TaksScheme;
    }
    */
    static void simple_xor_cipher(uint8_t *out, const uint8_t *in, size_t size, uint8_t *k) {
        for (int i = 0; i < size; ++i) {
            out[i] = in[i] ^ k[i % KEYLEN];
        }
    }

    static void simple_checksum_mac(std::array<uint8_t, MACLEN>& out, const uint8_t *in, size_t size, uint8_t *k) {
        uint32_t checksum = 0;
        for (int i = 0; i < size; ++i) {
            checksum += (uint32_t) in[i];
        }
        uint8_t n = 0;
        for (int i = 0; i < MACLEN; ++i) {
            out[i] = ((checksum >> n) & 0xFF) ^ k[i % KEYLEN];
            n = (n + 8) % 32; // repeat checksum bytes
        }
    }

    static void tak(TaksKeyComponent<KEYLEN> &out_ss, const TaksKeyComponent<KEYLEN*2> &c1, const TaksKeyComponent<KEYLEN*2> &c2) {
        return vector_mult(out_ss, c1, c2);
    }

    static void getNonce(TaksKeyComponent<KEYLEN*2> &out) {
        std::random_device randomdev;
        std::mt19937 prng {randomdev()};
        std::uniform_int_distribution<std::mt19937::result_type> distrib(0,0xFF);
        for (int i = 0; i < KEYLEN; ++i) {
            // we clone the x and y coordinate to simplify element-wise multiplications
            out.getX()[i] = out.getY()[i] = distrib(prng);
            //out.getX()[i] = out.getY()[i] = 0x01; // FIXME
        }
    }

    static uint8_t galois_mult(uint8_t a, uint8_t b) {
        uint8_t p = 0;
        while (a && b) {
            if (b & 1) p ^= a;
            if (a & 0x80) a = (a << 1) ^ POLY;
            else a <<= 1;
            b >>= 1;
        }
        return p;
    }

    static void elementwise_mult(TaksKeyComponent<KEYLEN*2> &out, const TaksKeyComponent<KEYLEN*2> &c1, const TaksKeyComponent<KEYLEN*2> &c2) {
        uint8_t *ss = out.getX();
        const uint8_t *p1 = c1.getX();
        const uint8_t *p2 = c2.getX();
        for (int i = 0; i < KEYLEN*2; ++i) {
            ss[i] = galois_mult(p1[i], p2[i]);
        }
    }

    static void vector_mult(TaksKeyComponent<KEYLEN> &out_ss, const TaksKeyComponent<KEYLEN*2> &c1, const TaksKeyComponent<KEYLEN*2> &c2) {
        uint8_t *ss = out_ss.getX();
        const uint8_t *p1x = c1.getX();
        const uint8_t *p1y = c1.getY();
        const uint8_t *p2x = c2.getX();
        const uint8_t *p2y = c2.getY();

        for (int i = 0; i < KEYLEN; ++i) {
            ss[i] = galois_mult(p1x[i], p2x[i]) ^ galois_mult(p1y[i], p2y[i]);
        }
    }
};


}

#endif /* end of IEEE802154eDSME_TAKS_H_ */
