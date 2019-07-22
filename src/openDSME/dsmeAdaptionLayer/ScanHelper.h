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

#ifndef SCANHELPER_H_
#define SCANHELPER_H_

#include "../helper/DSMEDelegate.h"
#include "../mac_services/MacDataStructures.h"
#include "../mac_services/dataStructures/PANDescriptor.h"
#include "../mac_services/mlme_sap/helper/PanDescriptorList.h"
#include "../mac_services/pib/PHY_PIB.h"

namespace dsme {

class DSMEAdaptionLayer;

namespace mlme_sap {
struct SYNC_LOSS_indication_parameters;
struct BEACON_NOTIFY_indication_parameters;
struct SCAN_confirm_parameters;
} /* namespace mlme_sap */

struct DSMEPANDescriptor;

class ScanHelper {
public:
    typedef Delegate<void(PANDescriptor*)> scanAndSyncCompleteDelegate_t;
    typedef Delegate<void()> syncLossAfterSyncedDelegate_t;

    explicit ScanHelper(DSMEAdaptionLayer&);

    void initialize(channelList_t& scanChannels, uint8_t scanDuration);

    void startScan();

    void setScanAndSyncCompleteDelegate(scanAndSyncCompleteDelegate_t delegate);

    void setSyncLossAfterSyncedDelegate(syncLossAfterSyncedDelegate_t delegate);

private:
    void handleBEACON_NOTIFY_indication(mlme_sap::BEACON_NOTIFY_indication_parameters&);

    void handleSCAN_confirm(mlme_sap::SCAN_confirm_parameters&);

    void handleSyncLossIndication(mlme_sap::SYNC_LOSS_indication_parameters&);

private:
    DSMEAdaptionLayer& dsmeAdaptionLayer;
    PanDescriptorList recordedPanDescriptors;
    scanAndSyncCompleteDelegate_t scanAndSyncCompleteDelegate;
    syncLossAfterSyncedDelegate_t syncLossAfterSyncedDelegate;

    MacStaticList<uint16_t, 8> heardCoordinators;
    uint8_t passiveScanCounter;
    channelList_t scanChannels;
    uint8_t scanDuration;
    PANDescriptor panDescriptorToSyncTo;
    bool syncActive;
};

} /* namespace dsme */

#endif /* SCANHELPER_H_ */
