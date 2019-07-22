/*
 * openDSME
 *
 * Implementation of the Deterministic & Synchronous Multi-channel Extension (DSME)
 * described in the IEEE 802.15.4-2015 standard
 *
 * Authors: Florian Kauer <florian.kauer@tuhh.de>
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

#include "./POLL.h"

#include "../../dsmeLayer/DSMELayer.h"
#include "../../dsmeLayer/messageDispatcher/MessageDispatcher.h"
#include "../../dsmeLayer/messages/IEEE802154eMACHeader.h"
#include "../../dsmeLayer/messages/MACCommand.h"
#include "../../interfaces/IDSMEMessage.h"
#include "../../interfaces/IDSMEPlatform.h"
#include "../pib/MAC_PIB.h"

namespace dsme {
namespace mlme_sap {

POLL::POLL(DSMELayer& dsme) : dsme(dsme) {
}

void POLL::request(request_parameters& params) {
    IDSMEMessage* msg = dsme.getPlatform().getEmptyMessage();

    /*IEEE802.15.4-2011 5.3.4*/
    MACCommand cmd;
    cmd.setCmdId(CommandFrameIdentifier::DATA_REQUEST);
    cmd.prependTo(msg);

    msg->getHeader().setDstAddrMode(params.coordAddrMode);
    msg->getHeader().setDstPANId(params.coordPanId);
    msg->getHeader().setDstAddr(params.coordAddress);

    /* 0xffff means unassociated, 0xfffe means short address not yet allocated */
    if(dsme.getMAC_PIB().macShortAddress < 0xfffe) {
        msg->getHeader().setSrcAddrMode(SHORT_ADDRESS);
        IEEE802154MacAddress sourceAddress(dsme.getMAC_PIB().macShortAddress);
        msg->getHeader().setSrcAddr(sourceAddress);
    } else {
        msg->getHeader().setSrcAddrMode(EXTENDED_ADDRESS);
        msg->getHeader().setSrcAddr(dsme.getMAC_PIB().macExtendedAddress);
    }

    msg->getHeader().setAckRequest(true);

    msg->getHeader().setFrameType(IEEE802154eMACHeader::FrameType::COMMAND);

    if(!dsme.getMessageDispatcher().sendInCAP(msg)) {
        // TODO ?
        dsme.getPlatform().releaseMessage(msg);
    }
}

} /* namespace mlme_sap */
} /* namespace dsme */
