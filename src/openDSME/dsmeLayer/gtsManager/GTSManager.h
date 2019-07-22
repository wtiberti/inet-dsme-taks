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

#ifndef GTSMANAGER_H_
#define GTSMANAGER_H_

#include "../../../DSMEMessage.h"
#include "../../helper/DSMEBufferedMultiFSM.h"
#include "../../helper/DSMEFSM.h"
#include "../../helper/Integers.h"
#include "../../mac_services/DSME_Common.h"
#include "../../mac_services/mlme_sap/DSME_GTS.h"
#include "../messages/GTSManagement.h"
#include "../messages/GTSReplyNotifyCmd.h"
#include "../messages/GTSRequestCmd.h"
#include "../messages/IEEE802154eMACHeader.h"
#include "../neighbors/NeighborQueue.h"
#include "./ACTUpdater.h"
#include "./GTSData.h"

namespace dsme {
class IDSMEMessage;
} /* namespace dsme */

constexpr uint8_t GTS_STATE_MULTIPLICITY = 4;

namespace dsme {

class DSMELayer;

class GTSEvent : public MultiFSMEvent {
public:
    template <typename... Args>
    void fill(uint16_t signal, Args&... args) {
        this->signal = signal;
        fill(args...);
    }

    enum : uint8_t { MLME_REQUEST_ISSUED = USER_SIGNAL_START, MLME_RESPONSE_ISSUED, RESPONSE_CMD_FOR_ME, NOTIFY_CMD_FOR_ME, CFP_STARTED, SEND_COMPLETE };

    uint16_t deviceAddr;
    GTSManagement management;
    GTSRequestCmd requestCmd;
    GTSReplyNotifyCmd replyNotifyCmd;
    IEEE802154eMACHeader header;
    CommandFrameIdentifier cmdId;
    DataStatus::Data_Status dataStatus;

private:
    static void fill(void);

    void fill(IDSMEMessage* msg, GTSManagement& management, CommandFrameIdentifier cmdId, DataStatus::Data_Status dataStatus);

    void fill(uint16_t& deviceAddr, GTSManagement& management, GTSReplyNotifyCmd& replyNotifyCmd);

    void fill(uint16_t& deviceAddr, GTSManagement& management, GTSRequestCmd& requestCmd);

    void fill(IDSMEMessage* msg, GTSManagement& management, GTSReplyNotifyCmd& replyNotifyCmd);
};

class GTSManager;

typedef DSMEBufferedMultiFSM<GTSManager, GTSEvent, GTS_STATE_MULTIPLICITY, GTS_STATE_MULTIPLICITY> GTSManagerFSM_t;

class GTSManager : private GTSManagerFSM_t {
public:
    explicit GTSManager(DSMELayer& dsme);

    void initialize();

    void reset();

    /*
     * For external calling from upper layer (over MLME.request).
     * Request for allocating  new GTSSlots to specified Address.
     *
     * @param deviceAddr The address of the respective other device
     * @param gtsManagement The management field of the MLME Request
     * @param gtsRequestAllocationCmd The request command field of the MLME Request
     *
     * @return false if the GTSManager is busy and can not handle the request, true otherwise
     */
    bool handleMLMERequest(uint16_t deviceAddr, GTSManagement& gtsManagement, GTSRequestCmd& gtsRequestAllocationCmd);

    /*
     * Called on reception of a GTS-response from upper layer.
     * Handles the response.
     *
     * @param gtsManagement The management field of the MLME Response
     * @param gtsReply The reply command field of the MLME Response
     *
     * @return false if the GTSManager is busy and can not handle the response, true otherwise
     */
    bool handleMLMEResponse(GTSManagement& gtsManagement, GTSReplyNotifyCmd& gtsReply);

    /**
     * Called on reception of a GTS-request.
     * Send request to upper layer.
     *
     * @param msg The received message. Might be modified afterwards (even in case of false),
     *            but the caller still owns the memory and has to release it.
     *
     * @return false if the GTSManager is busy and can not handle the message, true otherwise
     */
    bool handleGTSRequest(IDSMEMessage* msg);

    /**
     * Update slot allocation
     * Request initiator then sends GTS Notify to its neighbors.
     *
     * @param msg The received message. Might be modified afterwards (even in case of false),
     *            but the caller still owns the memory and has to release it.
     *
     * @return false if the GTSManager is busy and can not handle the message, true otherwise
     */
    bool handleGTSResponse(IDSMEMessage* msg);

    /**
     * Update slot allocation on reception of GTS Notify
     *
     * @param msg The received message. Might be modified afterwards (even in case of false),
     *            but the caller still owns the memory and has to release it.
     *
     * @return false if the GTSManager is busy and can not handle the message, true otherwise
     */
    bool handleGTSNotify(IDSMEMessage* msg);

    /**
     * This shall be called at the start of every CFP.
     *
     * @param superframe The superframe number
     *
     * @return false if the GTSManager is busy and can not handle the event, true otherwise
     */
    bool handleStartOfCFP(uint8_t superframe);

    /**
     * Gets called when CSMA Message was sent down to the PHY
     *
     * @param msg The received message. Might be modified afterwards (even in case of false),
     *            but the caller still owns the memory and has to release it.
     * @param cmdId The command ID of the sent message.
     * @param status The data status of the sent message.
     * @param numBackoffs The total number of backoffs required to sent or drop the message.
     *
     * @return false if the GTSManager is busy and can not handle the message, true otherwise
     */
    bool onCSMASent(IDSMEMessage* msg, CommandFrameIdentifier cmdId, DataStatus::Data_Status status, uint8_t numBackoffs);

private:
    /**
     * States
     */
    fsmReturnStatus stateBusy(GTSEvent& event);
    fsmReturnStatus stateIdle(GTSEvent& event);
    fsmReturnStatus stateSending(GTSEvent& event);
    fsmReturnStatus stateWaitForResponse(GTSEvent& event);
    fsmReturnStatus stateWaitForNotify(GTSEvent& event);

    /**
     * Actions
     */
    void actionSendImmediateNegativeResponse(GTSEvent& event);
    void actionReportBusyNotify(GTSEvent& event);
    void actionReportBusyCommStatus(GTSEvent& event);
    void actionProcessOverhearedResponse(GTSEvent& event);

    /**
     * Internal helper
     */
    bool sendGTSCommand(uint8_t fsmId, IDSMEMessage* msg, GTSManagement& man, CommandFrameIdentifier commandId, uint16_t dst, bool reportOnSent = true);
    bool checkAndHandleGTSDuplicateAllocation(DSMESABSpecification& sabSpec, uint16_t addr, bool allChannels);
    unsigned getNumAllocatedGTS(bool direction);
    void sendNotify(GTSReplyNotifyCmd& reply, uint16_t sourceAddr, GTSManagement& man);
    bool isTimeoutPending(uint8_t fsmId);
    void preparePendingConfirm(GTSEvent& event);

    static const char* signalToString(uint8_t signal);
    static const char* stateToString(GTSManagerFSM_t::state_t state);

    /**
     * FSM identification helpers
     */
    int8_t getFsmIdIdle();
    int8_t getFsmIdForRequest();
    int8_t getFsmIdForResponse(uint16_t destinationAddress);
    int8_t getFsmIdFromResponseForMe(IDSMEMessage* msg);
    int8_t getFsmIdFromNotifyForMe(IDSMEMessage* msg);

    bool hasBusyFsm();

    /*
     * Attributes
     */
    DSMELayer& dsme;
    ACTUpdater actUpdater;
    GTSData data[GTS_STATE_MULTIPLICITY + 1];
};

} /* namespace dsme */

#endif /* GTSMANAGER_H_ */
