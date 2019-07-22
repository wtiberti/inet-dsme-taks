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
#ifndef IEEE802154eDSME_GENERICPAYLOAD_H_
#define IEEE802154eDSME_GENERICPAYLOAD_H_

#include <cstdint>
#include <vector>
#include <string>
#include "../../mac_services/dataStructures/DSMEMessageElement.h"

namespace dsme {

class GenericPayload : public DSMEMessageElement {
public:
    GenericPayload() {
        data.clear();
        data.push_back(0);
    }

    GenericPayload(const std::string& s) {
        data.clear();
        fromString(s);
    }

    void fill(uint8_t value) {
        for (int i = 1; i < data.size(); ++i)
            data[i] = value;
    }

    uint8_t raw_fill(const uint8_t *ptr, uint8_t size) {
        int i;
        data.clear();
        data.push_back(size);
        for (i = 1; i < size; ++i)
            data.push_back(ptr[i]);
        return i;
    }

    void fromString(const std::string &s) {
        data.clear();
        data.push_back(s.size());
        data.insert(data.begin()+1, s.begin(), s.end());
    }

    void fromVector(const std::vector<uint8_t>& v) {
        data.clear();
        data[0] = v.size();
        for (const auto& e : v) {
            data.push_back(e);
        }
    }

    std::vector<uint8_t>& raw_data() {
        return data;
    }

public: // override
    virtual uint8_t getSerializationLength() override {
        return (uint8_t) data.size();
    }

    virtual void serialize(Serializer& serializer) override {
        if(serializer.getType() == serialization_type_t::SERIALIZATION) {
            uint8_t*& destdata = serializer.getDataRef();
            for (int i = 0; i < data.size(); ++i)
                destdata[i] = data[i];
        }
        else {
            const uint8_t *srcdata = serializer.getDataRef();
            uint8_t len = *srcdata;
            for (int i = 0; i < len; ++i)
                data[i] = srcdata[i];
            serializer.getDataRef() += data.size();
        }
        return;
    }
private:
    std::vector<uint8_t> data;
};
}
#endif // end of IEEE802154eDSME_GENERICPAYLOAD_H_
