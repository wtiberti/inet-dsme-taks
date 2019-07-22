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

#ifndef IEEE802154eDSME_DESTAK_H_
#define IEEE802154eDSME_DESTAK_H_

#include "config.h"
#include <chrono>

namespace dsme {
//using Taks = Taks<TAKS_KEY_LEN, RIJNDAEL_POLY, TAKS_MAC_LEN>;

IDSMEMessage *EncryptFrame(IDSMEMessage *imsg)
{
    DSMEMessage *msg = static_cast<DSMEMessage*>(imsg);
#if (ENABLE_SECURITY_ALL == 1)
    auto& header = msg->getHeader();

    std::chrono::system_clock::time_point start = std::chrono::system_clock::now();
    header.setSecurityEnabled(true);

    header.setIEListPresent(true);

    // create "random" payload
    std::string temp {"test-DATA"};
    msg->getPayload().fromString(temp);

    // TODO - implement a key manager - for now, example keycomp:
    TaksKeyComponent<TAKS_KEY_LEN*2> lkc;
    TaksKeyComponent<TAKS_KEY_LEN*2> tv;
    TaksKeyComponent<TAKS_KEY_LEN*2> tkc;
#if TAKS_KEY_LEN == 8
    // 64 bit keys
    lkc.fromHexString("EF87CE831431A45D01BE26F6324BDEA5");
    tv.fromHexString("CA091AE12B1241D9950A185BF82368F1");
    tkc.fromHexString("DB952560BC572E720977A9B4E67E639D");
#elif TAKS_KEY_LEN == 16
    // 128 bit keys
    lkc.fromHexString("dc9aef24729a362c890bfd1f349674c6a2024cabd81462942d6b58166ce928b7");
    tv.fromHexString("aeaaabf2905e10ee0fb1d04b8627c418b2be37200d3399d84b37f03dafe752c1");
    tkc.fromHexString("f8b7b97a8953f1128bb1efd0595a05e6110be9d740710214a9a5a73a12ef0f7f");
#elif TAKS_KEY_LEN == 24
    // 64 bit keys
    lkc.fromHexString("A6F4E5279A2719713B3E43FDEFE2AE93F76727A9BD8734E928351ED54A8B289E5AA5D447B6EB7F42067E7DAA14C52A3F");
    tv.fromHexString("A39B7D70EC69A88CD44A08326B55F323A6E6BFC9A7651B38A0B231DBE2F570EB1BB6E29FFA049759C9F0C955C6B466BA");
    tkc.fromHexString("94D4DE2E54AC71271284DB0DC5689C6BEE0C5C037BACB2BF8CB0CB469B759DA33DB3C9CF77633ECB0F0D0E4897D5AA03");
#elif TAKS_KEY_LEN == 32
    // 256 bit keys
    lkc.fromHexString("FC0CDDE25E53DB1FA3978C7C75E59A73C0B85B8081F6C011C436354AB32E15EB1D7D82CE03659E5C8B182932C5EA73734032F235081EC5D53554ACE762F707FA");
    tv.fromHexString("59E1DD91046B53EFD919FEB0CDC42F925E147446A6B27A9A299AFF3310A51E254ED431288C5A4228B913CFEE0C2364D2934DE156A4CD868C50FD27A80C966CF9");
    tkc.fromHexString("D50CA5A1D7DA686DC920294D1A5D851791A337E25C65148105736966B99E4B9AEE824AB67C7EC4D48C23FC0F78085A3F427CF2D62BBB547E080EA57B0FC965D6");
#endif
    TaksKeyComponent<TAKS_KEY_LEN*2> kri;
    std::array<uint8_t, TAKS_MAC_LEN> mac;

    uint8_t datasize = temp.size(); // it is the same for plain/cipher text
    uint8_t *cipherbuffer = new uint8_t[datasize];
    uint8_t *datastart = msg->getPayload().raw_data().data();
    // Encrypt
    Taks<TAKS_KEY_LEN, RIJNDAEL_POLY, TAKS_MAC_LEN>::Encrypt(cipherbuffer, datasize, datastart+1, datasize, mac, kri, lkc, tkc, tv);
    // no need to update the size
    for (int i = 0; i < datasize; ++i) {
        msg->getPayload().raw_data()[i+1] = cipherbuffer[i];
    }
    delete[] cipherbuffer;
    cipherbuffer = nullptr;

    header.getTaksIE().setKRI(kri);
    header.getTaksIE().setMAC(mac);

    std::chrono::system_clock::time_point end = std::chrono::system_clock::now();
    std::chrono::duration<double> duration = end - start;
    double seconds = duration.count();
    LOG_INFO("\nTAKS Encryption:" << seconds);
#endif
    return msg;
}

IDSMEMessage *DecryptFrame(IDSMEMessage *imsg, bool *success)
{
#if (ENABLE_SECURITY_ALL == 1)
    DSMEMessage *m = static_cast<DSMEMessage*>(imsg);
    auto& macHdr = m->getHeader();
    std::chrono::system_clock::time_point start = std::chrono::system_clock::now();
    //

    inet::Packet *p = m->getPacket();
    auto c = p->popAtBack().get();
    auto v = dynamic_cast<const inet::BytesChunk*>(c)->getBytes();
    GenericPayload& gp = m->getPayload();
    gp.fromVector(v);
    //
    TaksKeyComponent<TAKS_KEY_LEN*2>& kri = macHdr.getTaksIE().getKRI();
    std::array<uint8_t, TAKS_MAC_LEN>& mac = macHdr.getTaksIE().getMAC();

    // TODO - implement a key manager - for now, example keycomp:
    TaksKeyComponent<TAKS_KEY_LEN*2> lkc;

    #if TAKS_KEY_LEN == 8
    // 64 bit key
    lkc.fromHexString("45D1A5F69A6AF9DAA6BA0E52705029E8");
    #elif TAKS_KEY_LEN == 16
    // 128 bit key
    lkc.fromHexString("93bedde50e7eefdab02b40b7f68a5b2070a14b0b33ce4160d4df1868c2598692");
    #elif TAKS_KEY_LEN == 24
    // 192 bit key
    lkc.fromHexString("43AFD9D3A6B1D0FB43D5AE287971A49558AFEE13E84D6CCD73F6875F82483DFFBCA06645572923C74B473F78BEC89E66");
    #elif TAKS_KEY_LEN == 32
    // 256 bit key
    lkc.fromHexString("FC0CDDE25E53DB1FA3978C7C75E59A73C0B85B8081F6C011C436354AB32E15EB1D7D82CE03659E5C8B182932C5EA73734032F235081EC5D53554ACE762F707FA");
    #endif

    const uint8_t datasize = gp.getSerializationLength() - 1;
    uint8_t *plainbuffer = new uint8_t[datasize];

    // Auth. & Decrypt
    int result = Taks<TAKS_KEY_LEN, RIJNDAEL_POLY, TAKS_MAC_LEN>::Decrypt(plainbuffer, datasize, gp.raw_data().data()+1, datasize, mac, kri, lkc);
    if (result != -1) {
        // if success...
        // gp.raw_data[i] = datasize; // not needed
        for (int i = 0; i < datasize; ++i) {
            gp.raw_data()[i+1] = plainbuffer[i];
        }

        *success = true;

        std::chrono::system_clock::time_point end = std::chrono::system_clock::now();
        std::chrono::duration<double> duration = end - start;
        double seconds = duration.count();
        LOG_INFO("\nTAKS Decryption (success):" << seconds);
    }
    else {
        *success = false;

        std::chrono::system_clock::time_point end = std::chrono::system_clock::now();
        std::chrono::duration<double> duration = end - start;
        double seconds = duration.count();
        LOG_INFO("\nTAKS Decryption (fail):" << seconds);
    }
    delete[] plainbuffer;
    plainbuffer = nullptr;
#endif
    return imsg;
}

}; // dsme namespace
#endif
