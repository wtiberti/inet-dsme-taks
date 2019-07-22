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

#ifndef IEEE802154e_IE_TAKS_H_
#define IEEE802154e_IE_TAKS_H_

#include <stdlib.h>
#include <string>
#include <array>
#include <algorithm>
#include "../../mac_services/dataStructures/IE.h"

#include "../security/TAKS.h"

namespace dsme {
    template<size_t KEYLEN, size_t MACLEN>
    class TAKS_IE : public IEEE802154eHeaderIE {
    public:
        TAKS_IE() {
            IEEE802154eHeaderIE();
            setElementId(IE_EID_TAKS);
            setLength(MACLEN + KEYLEN*2);
            // Testing data
            KRI.fill(0xAA);
            tau.fill(0xBB);
        }

        void setKRI(TaksKeyComponent<KEYLEN*2>& kri) {
            KRI = kri; // No need for operator overloading, plain byte-level copy is enough
        }

        TaksKeyComponent<KEYLEN*2>& getKRI() {
            return KRI;
        }

        std::array<uint8_t, MACLEN>& getMAC() {
            return tau;
        }

        void setMAC(std::array<uint8_t, MACLEN>& mac) {
            tau = mac;
        }

        std::vector<uint8_t> serializeToVector() const {
            std::vector<uint8_t> result;
            uint16_t hdr = serializeHeader();
            result.push_back(hdr >> 8);
            result.push_back(hdr & 0xFF);
            for (int i = 0; i < KEYLEN*2; ++i)
                result.push_back(KRI.getX()[i]);
            for (int i = 0; i < MACLEN; ++i)
                result.push_back(tau[i]);
            return result;
        }

        size_t fromBytes(const uint8_t *buffer) {
            int i, j;
            IEEE802154eHeaderIE(*buffer, *(buffer+1));
            uint8_t *p = ((uint8_t *)buffer) + 2;
            for (i = 0; i < KEYLEN*2; ++i)
                KRI.getX()[i] = p[i];
            for (j = 0; j < MACLEN; ++j)
                tau[j] = p[i+j];
            return 2 + i + j;
        }

        virtual size_t getSize() const override {
            return 2 + KEYLEN*2 + MACLEN;
        }
    private:
        TaksKeyComponent<KEYLEN*2> KRI;
        std::array<uint8_t, MACLEN> tau;
    };
}
#endif /* end of IEEE802154e_IE_TAKS_H_ */
