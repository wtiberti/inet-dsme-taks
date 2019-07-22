/*
 * openDSME
 *
 * Implementation of the Deterministic & Synchronous Multi-channel Extension (DSME)
 * introduced in the IEEE 802.15.4e-2012 standard
 *
 * Authors: Florian Meier <florian.meier@tuhh.de>
 *          Maximilian Koestler <maximilian.koestler@tuhh.de>
 *          Sandrina Backhauss <sandrina.backhauss@tuhh.de>
 *
 * Based on
 *          DSME Implementation for the INET Framework
 *          Tobias Luebkert <tobias.luebkert@tuhh.de>
 *
 * Copyright (c) 2015, Institute of Telematics, Hamburg University of Technology
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef PHY_PIB_H_
#define PHY_PIB_H_

#include "../MacDataStructures.h"

namespace dsme {

typedef MacStaticList<uint8_t, 16> channelList_t;

/*
 * This class contains PHY PIB attributes as defined in IEEE 802.15.4-2011, 9.3, Table 71
 */
class PHY_PIB {
public:
    PHY_PIB();
    ~PHY_PIB();

    void setDSSS2450ChannelPage(channelList_t& DSSS2450_channels);

    /** The RF channel to use for all following transmissions and receptions, 10.1.2.
     * Though it is not clearly described in the standard, we assume this value shall not be changed during channel
     * hopping or channel adaption. For example IEEE 802.15.4-2015 6.3.3.4 does only mention the channel of MLME-START
     * shall be written to this value, so there seems to be no other way to store the common channel.
     */
    uint8_t phyCurrentChannel{11};

    /** The transmit power of the device in dBm. */
    int16_t phyTxPower{0};

    /** This is the current PHY channel page. This is used in conjunction with phyCurrentChannel to uniquely identify the channel currently being used. */
    uint8_t phyCurrentPage{0};

    /** Each entry in the list consists of a channel page and a list of channel numbers supported for that channel page. */
    MacStaticList<MacTuple<uint8_t, channelList_t>*, 8> phyChannelsSupported;

    /** TRUE if ranging is supported, FALSE otherwise. */
    bool phyRanging{false};

    /* The number of symbols per octet for the current PHY. For the UWB PHY this is defined in 14.2.3. For the CSS PHY,
     * 1.3 corresponds to 1 Mb/s while 5.3 corresponds to 250 kb/s. */
    const float phySymbolsPerOctet{2.0};

    uint8_t phySHRDuration{10};
};

} /* namespace dsme */

#endif /* PHY_PIB_H_ */
