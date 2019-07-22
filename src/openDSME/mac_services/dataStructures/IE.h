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

#ifndef IEEE802154eIE_H_
#define IEEE802154eIE_H_

#include <stdint.h>

namespace dsme {
    /* Interface for IEs */

    class IEEE802154eIE {
    public:
        virtual void setLength(uint16_t length) = 0;
        virtual bool isPayloadIE() const = 0;
        virtual uint16_t serializeHeader() const = 0;
        virtual uint16_t length() const = 0;
        virtual size_t getSize() const = 0;
    };

    /* Generic structure for Header IE */
    struct HeaderIEHeader {
        uint16_t length : 7;
        uint16_t elem_id : 8;
        uint16_t type : 1;

    public:
        operator uint16_t () const {
           return (length << 9) | (elem_id << 1) | type;
        }
    };

    // See table 7.7 pag 170 (IEEE 802.15.4-2015)
    enum HeaderIeElementID : uint8_t {
        IE_EID_VENDORSPECIFIC = 0x00,
        /* 0x1 -> 0x19 reserved */
        IE_EID_CSL = 0x1A,
        IE_EID_RIT = 0x1B,
        IE_EID_DSMEPANDESC = 0x1C,
        IE_EID_RENDEZTIME = 0x1D,
        IE_EID_TIMECORRECT = 0x1E,
        /* 0x1f -> 0x20 reserved */
        IE_EID_EXTDSMEPANDESC = 0x21,
        IE_EID_FSCD = 0x22,
        IE_EID_SIMPLESUPERFRAMESPEC = 0x23,
        IE_EID_SIMPLEGTSSPEC = 0x24,
        IE_EID_LECIMCAP= 0x25,
        IE_EID_TRLE = 0x26,
        IE_EID_RCCN = 0x27,
        IE_EID_GLOBALTIME = 0x28,
        IE_EID_EXTORG = 0x29,
        IE_EID_DA = 0x2A,
        /* 0x2B -> 0x7D reserved */
        /* TAKS uses 0x2B */
        IE_EID_TAKS = 0x2B,
        /******************/
        IE_EID_HT1 = 0x7E,
        IE_EID_HT2 = 0x7F,
        /* 0x80 -> 0xFF reserved */
    };

    /* Child class for the Header IE */

    class IEEE802154eHeaderIE : public IEEE802154eIE {
    public:
        IEEE802154eHeaderIE() {
            ie.type = 0;
        }

        IEEE802154eHeaderIE(uint8_t byte1, uint8_t byte2) {
            ie.type = 0;
            setLength((byte1 >> 1) & 0b1111111);
            uint8_t elementid = ((byte1 & 1) << 7) | ((byte2 & 0xFE) >> 1);
            setElementId((HeaderIeElementID)int(elementid));
        }

        uint8_t elementId() const {
            return (uint8_t) ie.elem_id;
        }

        void setElementId(HeaderIeElementID id) {
            ie.elem_id = (uint8_t) id;
        }

        uint16_t length() const override {
            return ie.length;
        }

        void setLength(uint16_t length) override {
            length &= 0b1111111;
            ie.length = length;
        }

        bool isPayloadIE() const override {
            return false;
        }

        uint16_t serializeHeader() const override {
            return (uint16_t)ie;
        }

        virtual size_t getSize() const override {
            return 2;
        }

    protected:
        HeaderIEHeader ie;
    };


    /* Generic structure for Payload IE */
    struct PayloadIEHeader {
        uint16_t length : 11;
        uint16_t group_id : 4;
        uint16_t type : 1;
    public:
        operator uint16_t () const {
           return (length << 5) | (group_id << 1) | type;
        }
    };

    enum PayloadIeGroupID : uint8_t {
        IE_GID_ESDU = 0b0000,
        IE_GID_MLME = 0b0001,
        IE_GID_VENDORSPEC = 0b0010,
        /* 0x03 -> 0x0E reserved */
        IE_GID_PAYLOADTERM = 0b1111
    };


    /* Child class for the Payload IE */

    class IEEE802154ePayloadIE : public IEEE802154eIE {
    public:
        IEEE802154ePayloadIE() {
            ie.type = 1;
        }

        IEEE802154ePayloadIE(uint8_t byte1, uint8_t byte2) {
            ie.type = 1;
            uint16_t temp = uint16_t(byte1 << 8) | byte2;
            setLength((temp >> 5) & 0b11111111111);
            setGroupId((PayloadIeGroupID)int((byte2 & 0b11110) >> 1));
        };

        uint16_t length() const override {
            return ie.length;
        }

        void setLength(uint16_t length) override {
            length &= 0b11111111111;
            ie.length = length;
        }

        uint8_t groupId() const {
            return (uint8_t) ie.group_id;
        }

        void setGroupId(PayloadIeGroupID id) {
            ie.group_id = ((uint8_t)id) & 0b1111;
        }

        bool isPayloadIE() const override {
            return true;
        }

        uint16_t serializeHeader() const override {
            return (uint16_t)ie;
        }

        virtual size_t getSize() const override {
            return 2;
        }
    protected:
        PayloadIEHeader ie;
    };

    const IEEE802154eHeaderIE IE_Termination_HT1 {0x00, 0xFE};
    const IEEE802154eHeaderIE IE_Termination_HT2 {0x00, 0x7C};
}
#endif // end of IEEE802154eIE_H_
