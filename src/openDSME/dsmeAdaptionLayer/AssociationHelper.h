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

#ifndef ASSOCIATIONHELPER_H_
#define ASSOCIATIONHELPER_H_

#include "../helper/DSMEDelegate.h"
#include "../mac_services/DSME_Common.h"

namespace dsme {

class DSMEAdaptionLayer;
class IEEE802154MacAddress;

namespace mlme_sap {
struct ASSOCIATE_confirm_parameters;
struct ASSOCIATE_indication_parameters;
struct DISASSOCIATE_confirm_parameters;
} /* namespace mlme_sap */

class AssociationHelper {
public:
    typedef Delegate<void(AssociationStatus::Association_Status)> associationCompleteDelegate_t;
    typedef Delegate<void(DisassociationStatus::Disassociation_Status)> disassociationCompleteDelegate_t;

    explicit AssociationHelper(DSMEAdaptionLayer&);

    void initialize();

    void setAssociationCompleteDelegate(associationCompleteDelegate_t delegate);
    void setDisassociationCompleteDelegate(disassociationCompleteDelegate_t delegate);

    void associate(uint16_t coordPANId, AddrMode addrMode, IEEE802154MacAddress& coordAddress, uint8_t channel);

    void disassociate();

private:
    void handleASSOCIATION_indication(mlme_sap::ASSOCIATE_indication_parameters& params);
    void handleASSOCIATION_confirm(mlme_sap::ASSOCIATE_confirm_parameters& params);

    void handleDISASSOCIATION_confirm(mlme_sap::DISASSOCIATE_confirm_parameters& params);

    DSMEAdaptionLayer& dsmeAdaptionLayer;
    associationCompleteDelegate_t associationCompleteDelegate;
    disassociationCompleteDelegate_t disassociationCompleteDelegate;
};

} /* namespace dsme */

#endif /* ASSOCIATIONHELPER_H_ */
