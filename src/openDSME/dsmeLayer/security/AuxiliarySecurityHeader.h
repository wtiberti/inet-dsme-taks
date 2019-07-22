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

#ifndef IEEE802154eAUXSECHDR_H_
#define IEEE802154eAUXSECHDR_H_
#include <stdint.h>
namespace dsme {
    enum SecurityLevel : uint8_t {
        SECURITYLEVEL_NONE =      0b000,
        SECURITYLEVEL_MIC32 =     0b001,
        SECURITYLEVEL_MIC64 =     0b010,
        SECURITYLEVEL_MIC128 =    0b011,
        SECURITYLEVEL_RESV =      0b100,
        SECURITYLEVEL_ENCMIC32 =  0b101,
        SECURITYLEVEL_ENCMIC64 =  0b110,
        SECURITYLEVEL_ENCMIC128 = 0b111
    };

    enum KeyIdentifierMode : uint8_t {
        KEYIDMODE_IMPLICIT =        0b00,
        KEYIDMODE_FROM_KEY_INDEX  = 0b01,
        KEYIDMODE_FROM_SRC_FIELD4 = 0b10,
        KEYIDMODE_FROM_SRC_FIELD8 = 0b11
    };

    /* Auxiliary Security Header */
    struct SecurityControl {
        SecurityLevel security_level : 3;
        KeyIdentifierMode key_id_mode : 2;
        uint8_t frame_counter_suppression : 1;
        uint8_t asn_in_nonce : 1;
        uint8_t reserved : 1;
    } __attribute__((packed));

    struct KeyIdentifier {
        uint8_t key_source[8];
        uint8_t key_index;
    } __attribute__((packed));


    class AuxiliarySecurityHeader {
    public:
        AuxiliarySecurityHeader() {
            security_control.security_level = SECURITYLEVEL_ENCMIC128;
            security_control.key_id_mode = KEYIDMODE_IMPLICIT;
            security_control.frame_counter_suppression = 1;
            security_control.asn_in_nonce = 0;
            security_control.reserved = 0;

            frame_counter[0] = 0;
            frame_counter[1] = 0;
            frame_counter[2] = 0;
            frame_counter[3] = 0;

            key_identifier.key_index = 0;
        }

        void setSecurityControl(SecurityControl &sc) {
            security_control = sc;
        }

        void SecurityControlFromByte(uint8_t byte1) {
            security_control.security_level = (SecurityLevel) int((byte1 >> 5) & 0b111);
            security_control.key_id_mode = (KeyIdentifierMode) int((byte1 >> 3) & 0b11);
            security_control.frame_counter_suppression = (byte1 >> 2) & 1;
            security_control.asn_in_nonce = (byte1 >> 1) & 1;
            security_control.reserved = byte1 & 1;
        }

        SecurityControl& getSecurityControl() {
            return security_control;
        }

        const SecurityControl& getSecurityControl() const {
            return security_control;
        }

        void setFrameCounter(uint32_t value) {
            frame_counter[0] = (uint8_t) ((value >> 24) & 0xFF);
            frame_counter[1] = (uint8_t) ((value >> 16) & 0xFF);
            frame_counter[2] = (uint8_t) ((value >> 8) & 0xFF);
            frame_counter[3] = (uint8_t) (value & 0xFF);
        }

        uint32_t getFrameCounter() const {
            return ((frame_counter[3] << 24) & 0xFF000000) |
                    ((frame_counter[2] << 16) & 0x00FF0000) |
                    ((frame_counter[1] << 8) & 0x0000FF00)|
                    ((frame_counter[0]) & 0x000000FF);
        }

        operator uint8_t () const {
            uint8_t result = 0;
            result |= (security_control.security_level << 5);
            result |= (security_control.key_id_mode << 3);
            result |= (security_control.frame_counter_suppression << 2);
            result |= (security_control.asn_in_nonce << 1);
            return result;
        }

        uint8_t getSize() const {
            uint8_t result = 1;
            switch (security_control.key_id_mode) {
            case KEYIDMODE_FROM_KEY_INDEX:
                result += 1;
                break;
            case KEYIDMODE_FROM_SRC_FIELD4:
                result += 5;
                break;
            case KEYIDMODE_FROM_SRC_FIELD8:
                result += 9;
                break;
            default:
                result += 0;
            }
            if (security_control.frame_counter_suppression == 0)
                result += 4;
            return result;
        }
    private:
        struct SecurityControl security_control;
        uint8_t frame_counter[4];
        struct KeyIdentifier key_identifier;
    };
}
#endif /* end of IEEE802154eAUXSECHDR_H_ */
