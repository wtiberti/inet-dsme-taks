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
 * Contributed by: (openDSME-secure)
 *          Walter Tiberti <walter.tiberti@graduate.univaq.it>
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

#include "./MessageDispatcher.h"

#include "../../../dsme_platform.h"
#include "../../../dsme_settings.h"
#include "../../helper/DSMEDelegate.h"
#include "../../helper/Integers.h"
#include "../../interfaces/IDSMEMessage.h"
#include "../../interfaces/IDSMEPlatform.h"
#include "../../mac_services/DSME_Common.h"
#include "../../mac_services/MacDataStructures.h"
#include "../../mac_services/dataStructures/DSMEAllocationCounterTable.h"
#include "../../mac_services/dataStructures/IEEE802154MacAddress.h"
#include "../../mac_services/mcps_sap/DATA.h"
#include "../../mac_services/mcps_sap/MCPS_SAP.h"
#include "../../mac_services/pib/MAC_PIB.h"
#include "../../mac_services/pib/PHY_PIB.h"
#include "../../mac_services/pib/PIBHelper.h"
#include "../DSMELayer.h"
#include "../ackLayer/AckLayer.h"
#include "../associationManager/AssociationManager.h"
#include "../beaconManager/BeaconManager.h"
#include "../capLayer/CAPLayer.h"
#include "../gtsManager/GTSManager.h"
#include "../messages/IEEE802154eMACHeader.h"
#include "../messages/MACCommand.h"

#include "../security/DESTAK.h"

uint8_t mCh;

namespace dsme {

MessageDispatcher::MessageDispatcher(DSMELayer& dsme)
    : dsme(dsme),
      currentACTElement(nullptr, nullptr),
      doneGTS(DELEGATE(&MessageDispatcher::sendDoneGTS, *this)),
      dsmeAckFrame(nullptr),
      lastSendGTSNeighbor(neighborQueue.end()) {
}

MessageDispatcher::~MessageDispatcher() {
    for(NeighborQueue<MAX_NEIGHBORS>::iterator it = neighborQueue.begin(); it != neighborQueue.end(); ++it) {
        while(!this->neighborQueue.isQueueEmpty(it)) {
            IDSMEMessage* msg = neighborQueue.popFront(it);
            this->dsme.getPlatform().releaseMessage(msg);
        }
    }
}

void MessageDispatcher::initialize(void) {
    currentACTElement = dsme.getMAC_PIB().macDSMEACT.end();
    return;
}

void MessageDispatcher::reset(void) {
    currentACTElement = dsme.getMAC_PIB().macDSMEACT.end();

    for(NeighborQueue<MAX_NEIGHBORS>::iterator it = neighborQueue.begin(); it != neighborQueue.end(); ++it) {
        while(!this->neighborQueue.isQueueEmpty(it)) {
            IDSMEMessage* msg = neighborQueue.popFront(it);
            mcps_sap::DATA_confirm_parameters params;
            params.msduHandle = msg;
            params.timestamp = 0;
            params.rangingReceived = false;
            params.gtsTX = true;
            params.status = DataStatus::TRANSACTION_EXPIRED;
            params.numBackoffs = 0;
            this->dsme.getMCPS_SAP().getDATA().notify_confirm(params);
        }
    }
    while(this->neighborQueue.getNumNeighbors() > 0) {
        NeighborQueue<MAX_NEIGHBORS>::iterator it = this->neighborQueue.begin();
        this->neighborQueue.eraseNeighbor(it);
    }

    return;
}

void MessageDispatcher::finalizeGTSTransmission() {
    transceiverOffIfAssociated();
    this->lastSendGTSNeighbor = this->neighborQueue.end();
    this->currentACTElement = this->dsme.getMAC_PIB().macDSMEACT.end();
}

void MessageDispatcher::transceiverOffIfAssociated() {
    if(this->dsme.getMAC_PIB().macAssociatedPANCoord) {
        this->dsme.getPlatform().turnTransceiverOff();
    } else {
        /* '-> do not turn off the transceiver while we might be scanning */
    }
}

bool MessageDispatcher::handlePreSlotEvent(uint8_t nextSlot, uint8_t nextSuperframe, uint8_t nextMultiSuperframe) {
    // Prepare next slot
    // Switch to next slot channel and radio mode

    DSMEAllocationCounterTable& act = this->dsme.getMAC_PIB().macDSMEACT;

    if(this->currentACTElement != act.end()) {
        if(this->currentACTElement->getDirection() == Direction::RX) {
            this->currentACTElement = act.end();
        } else {
            // Rarely happens, only if the sendDoneGTS is delayed
            // Then skip this preSlotEvent
#if 1
            DSME_SIM_ASSERT(false);
#endif
            return false;
        }
    }

    if(nextSlot > this->dsme.getMAC_PIB().helper.getFinalCAPSlot(nextSuperframe)) {
        /* '-> next slot will be GTS */

        unsigned nextGTS = nextSlot - (this->dsme.getMAC_PIB().helper.getFinalCAPSlot(nextSuperframe) + 1);
        if(act.isAllocated(nextSuperframe, nextGTS)) {
            /* '-> this slot might be used */

            this->currentACTElement = act.find(nextSuperframe, nextGTS);
            DSME_ASSERT(this->currentACTElement != act.end());
            // For TX currentACTElement will be reset in finalizeGTSTransmission, called by
            // either handleGTS if nothing is to send or by sendDoneGTS.
            // For RX it is reset in the next handlePreSlotEvent.

            // For RX also if INVALID or UNCONFIRMED!
            if((this->currentACTElement->getState() == VALID) || (this->currentACTElement->getDirection() == Direction::RX)) {
                this->dsme.getPlatform().turnTransceiverOn();

                if(dsme.getMAC_PIB().macChannelDiversityMode == Channel_Diversity_Mode::CHANNEL_ADAPTATION) {
                    this->dsme.getPlatform().setChannelNumber(this->dsme.getMAC_PIB().helper.getChannels()[this->currentACTElement->getChannel()]);
                    mCh = this->currentACTElement->getChannel();
                } else {
                    /* Channel hopping: Calculate channel for given slotID */
                    uint16_t hoppingSequenceLength = this->dsme.getMAC_PIB().macHoppingSequenceLength;
                    uint8_t ebsn = 0; // this->dsme.getMAC_PIB().macPanCoordinatorBsn;    //TODO is this set correctly
                    uint16_t sdIndex = nextSuperframe + this->dsme.getMAC_PIB().helper.getNumberSuperframesPerMultiSuperframe() * nextMultiSuperframe;
                    uint8_t numGTSlots = this->dsme.getMAC_PIB().helper.getNumGTSlots(sdIndex);

                    uint8_t slotId = this->currentACTElement->getGTSlotID();
                    uint16_t channelOffset = this->currentACTElement->getChannel(); // holds the channel offset in channel hopping mode

                    uint8_t channel =
                        this->dsme.getMAC_PIB().macHoppingSequenceList[(sdIndex * numGTSlots + slotId + channelOffset + ebsn) % hoppingSequenceLength];
                    LOG_INFO("Using channel " << channel << " - numGTSlots: " << numGTSlots << " EBSN: " << ebsn << " sdIndex: " << sdIndex
                                              << " slot: " << slotId << " Superframe " << nextSuperframe << " channelOffset: " << channelOffset
                                              << " Direction: " << currentACTElement->getDirection());
                    this->dsme.getPlatform().setChannelNumber(channel);
                    mCh = channel;
                }
            }

            // statistic
            if(this->currentACTElement->getDirection() == RX) {
                this->numUnusedRxGts++; // gets PURGE.cc decremented on actual reception
            }
        } else {
            /* '-> nothing to do during this slot */
            DSME_ASSERT(this->currentACTElement == act.end());
            transceiverOffIfAssociated();
        }
    } else if(nextSlot == 0) {
        /* '-> beacon slots are handled by the BeaconManager */
        DSME_ASSERT(this->currentACTElement == act.end());
    } else if(nextSlot == 1) {
        /* '-> next slot will be CAP */

        if(!this->dsme.getMAC_PIB().macCapReduction || nextSuperframe == 0) {
            /* '-> active CAP slot */

            this->dsme.getPlatform().turnTransceiverOn();
            this->dsme.getPlatform().setChannelNumber(this->dsme.getPHY_PIB().phyCurrentChannel);
        } else {
            /* '-> CAP reduction */
            transceiverOffIfAssociated();
        }
    }

    return true;
}

bool MessageDispatcher::handleSlotEvent(uint8_t slot, uint8_t superframe, int32_t lateness) {
    if(slot > dsme.getMAC_PIB().helper.getFinalCAPSlot(superframe)) {
        handleGTS(lateness);
    }
    return true;
}

void MessageDispatcher::receive(IDSMEMessage* msg) {
    IEEE802154eMACHeader macHdr = msg->getHeader();

    switch(macHdr.getFrameType()) {
        case IEEE802154eMACHeader::FrameType::BEACON: {
            LOG_INFO("BEACON from " << macHdr.getSrcAddr().getShortAddress() << " " << macHdr.getSrcPANId() << " " << dsme.getCurrentSuperframe() << ".");
            this->dsme.getBeaconManager().handleBeacon(msg);
            this->dsme.getPlatform().releaseMessage(msg);
            break;
        }

        case IEEE802154eMACHeader::FrameType::COMMAND: {
            MACCommand cmd;
            cmd.decapsulateFrom(msg);
            switch(cmd.getCmdId()) {
                case CommandFrameIdentifier::DSME_GTS_REQUEST:
                    LOG_INFO("DSME-GTS-REQUEST from " << macHdr.getSrcAddr().getShortAddress() << ".");
                    dsme.getGTSManager().handleGTSRequest(msg);
                    break;
                case CommandFrameIdentifier::DSME_GTS_REPLY:
                    LOG_INFO("DSME-GTS-REPLY from " << macHdr.getSrcAddr().getShortAddress() << ".");
                    dsme.getGTSManager().handleGTSResponse(msg);
                    break;
                case CommandFrameIdentifier::DSME_GTS_NOTIFY:
                    LOG_INFO("DSME-GTS-NOTIFY from " << macHdr.getSrcAddr().getShortAddress() << ".");
                    dsme.getGTSManager().handleGTSNotify(msg);
                    break;
                case CommandFrameIdentifier::ASSOCIATION_REQUEST:
                    LOG_INFO("ASSOCIATION-REQUEST from " << macHdr.getSrcAddr().getShortAddress() << ".");
                    dsme.getAssociationManager().handleAssociationRequest(msg);
                    break;
                case CommandFrameIdentifier::ASSOCIATION_RESPONSE:
                    LOG_INFO("ASSOCIATION-RESPONSE from " << macHdr.getSrcAddr().getShortAddress() << ".");
                    dsme.getAssociationManager().handleAssociationReply(msg);
                    break;
                case CommandFrameIdentifier::DISASSOCIATION_NOTIFICATION:
                    LOG_INFO("DISASSOCIATION-NOTIFICATION from " << macHdr.getSrcAddr().getShortAddress() << ".");
                    dsme.getAssociationManager().handleDisassociationRequest(msg);
                    break;
                case CommandFrameIdentifier::DATA_REQUEST:
                    /* Not implemented */
                    break;
                case CommandFrameIdentifier::DSME_BEACON_ALLOCATION_NOTIFICATION:
                    LOG_INFO("DSME-BEACON-ALLOCATION-NOTIFICATION from " << macHdr.getSrcAddr().getShortAddress() << ".");
                    dsme.getBeaconManager().handleBeaconAllocation(msg);
                    break;
                case CommandFrameIdentifier::DSME_BEACON_COLLISION_NOTIFICATION:
                    LOG_INFO("DSME-BEACON-COLLISION-NOTIFICATION from " << macHdr.getSrcAddr().getShortAddress() << ".");
                    dsme.getBeaconManager().handleBeaconCollision(msg);
                    break;
                case CommandFrameIdentifier::BEACON_REQUEST:
                    LOG_INFO("BEACON_REQUEST from " << macHdr.getSrcAddr().getShortAddress() << ".");
                    dsme.getBeaconManager().handleBeaconRequest(msg);
                    break;
                default:
                    LOG_ERROR("Invalid cmd ID " << (uint16_t)cmd.getCmdId());
                    // DSME_ASSERT(false);
            }
            dsme.getPlatform().releaseMessage(msg);
            break;
        }

        case IEEE802154eMACHeader::FrameType::DATA: {
            if(currentACTElement != dsme.getMAC_PIB().macDSMEACT.end()) {
                /*TODO*/
                handleGTSFrame(msg);
            } else {
                createDataIndication(msg);
            }
            break;
        }

        default: {
            LOG_ERROR((uint16_t)macHdr.getFrameType());
            dsme.getPlatform().releaseMessage(msg);
        }
    }
    return;
}

void MessageDispatcher::createDataIndication(IDSMEMessage* msg) {
    IEEE802154eMACHeader& header = msg->getHeader();

    mcps_sap::DATA_indication_parameters params;

    params.msdu = msg;

    params.mpduLinkQuality = 0; // TODO link quality?
    params.dsn = header.getSequenceNumber();
    params.timestamp = msg->getStartOfFrameDelimiterSymbolCounter();
    params.securityLevel = header.isSecurityEnabled();

    params.dataRate = 0; // DSSS -> 0

    params.rangingReceived = NO_RANGING_REQUESTED;
    params.rangingCounterStart = 0;
    params.rangingCounterStop = 0;
    params.rangingTrackingInterval = 0;
    params.rangingOffset = 0;
    params.rangingFom = 0;

    this->dsme.getMCPS_SAP().getDATA().notify_indication(params);
}

bool MessageDispatcher::sendInGTS(IDSMEMessage* msg, NeighborQueue<MAX_NEIGHBORS>::iterator destIt) {
    DSME_ASSERT(!msg->getHeader().getDestAddr().isBroadcast());
    DSME_ASSERT(this->dsme.getMAC_PIB().macAssociatedPANCoord);
    DSME_ASSERT(destIt != neighborQueue.end());

    numUpperPacketsForGTS++;

#if (ENABLE_SECURITY_ALL == 1)
    msg = EncryptFrame(msg);
#endif

    if(!neighborQueue.isQueueFull()) {
        /* push into queue */
        // TODO implement TRANSACTION_EXPIRED
        uint16_t totalSize = 0;
        for(NeighborQueue<MAX_NEIGHBORS>::iterator it = neighborQueue.begin(); it != neighborQueue.end(); ++it) {
            totalSize += it->queueSize;
        }
        LOG_INFO("NeighborQueue is at " << totalSize << "/" << TOTAL_GTS_QUEUE_SIZE << ".");
        neighborQueue.pushBack(destIt, msg);
        return true;
    } else {
        /* queue full */
        LOG_INFO("NeighborQueue is full!");
        numUpperPacketsDroppedFullQueue++;
        return false;
    }
}

bool MessageDispatcher::sendInCAP(IDSMEMessage* msg) {
    numUpperPacketsForCAP++;
    LOG_INFO("Inserting message into CAP queue.");
    if(msg->getHeader().getSrcAddrMode() != EXTENDED_ADDRESS && !(this->dsme.getMAC_PIB().macAssociatedPANCoord)) {
        LOG_INFO("Message dropped due to missing association!");
        // TODO document this behaviour
        // TODO send appropriate MCPS confirm or better remove this handling and implement TRANSACTION_EXPIRED
        return false;
    }

    if(!this->dsme.getCapLayer().pushMessage(msg)) {
        LOG_INFO("CAP queue full!");
        return false;
    }

    return true;
}

void MessageDispatcher::handleGTS(int32_t lateness) {
    if(this->currentACTElement != this->dsme.getMAC_PIB().macDSMEACT.end() && this->currentACTElement->getSuperframeID() == this->dsme.getCurrentSuperframe() &&
       this->currentACTElement->getGTSlotID() ==
           this->dsme.getCurrentSlot() - (this->dsme.getMAC_PIB().helper.getFinalCAPSlot(dsme.getCurrentSuperframe()) + 1)) {
        /* '-> this slot matches the prepared ACT element */

        if(this->currentACTElement->getDirection() == RX) { // also if INVALID or UNCONFIRMED!
            /* '-> a message may be received during this slot */

        } else if(this->currentACTElement->getState() == VALID) {
            /* '-> if any messages are queued for this link, send one */

            DSME_ASSERT(this->lastSendGTSNeighbor == this->neighborQueue.end());

            IEEE802154MacAddress adr = IEEE802154MacAddress(this->currentACTElement->getAddress());
            this->lastSendGTSNeighbor = this->neighborQueue.findByAddress(IEEE802154MacAddress(this->currentACTElement->getAddress()));
            if(this->lastSendGTSNeighbor == this->neighborQueue.end()) {
                /* '-> the neighbor associated with the current slot does not exist */

                LOG_ERROR("neighborQueue.size: " << ((uint8_t) this->neighborQueue.getNumNeighbors()));
                LOG_ERROR("neighbor address: " << HEXOUT << adr.a1() << ":" << adr.a2() << ":" << adr.a3() << ":" << adr.a4() << DECOUT);
                for(auto it : this->neighborQueue) {
                    LOG_ERROR("neighbor address: " << HEXOUT << it.address.a1() << ":" << it.address.a2() << ":" << it.address.a3() << ":" << it.address.a4()
                                                   << DECOUT);
                }
                DSME_ASSERT(false);
            }

            if(this->neighborQueue.isQueueEmpty(this->lastSendGTSNeighbor)) {
                /* '-> no message to be sent */
                finalizeGTSTransmission();
                this->numUnusedTxGts++;
            } else {
                /* '-> a message is queued for transmission */

                IDSMEMessage* msg = neighborQueue.front(this->lastSendGTSNeighbor);
#if 1
                DSME_ASSERT(this->dsme.getMAC_PIB().helper.getSymbolsPerSlot() >= lateness + msg->getTotalSymbols() +
                                                                                      this->dsme.getMAC_PIB().helper.getAckWaitDuration() +
                                                                                      10 /* arbitrary processing delay */ + PRE_EVENT_SHIFT);
#endif
                bool result = this->dsme.getAckLayer().prepareSendingCopy(msg, this->doneGTS);
                if(result) {
                    /* '-> ACK-layer was ready, send message now
                     * sendDoneGTS might have already been called, then sendNowIfPending does nothing! */
                    this->dsme.getAckLayer().sendNowIfPending();
                } else {
                    /* '-> message could not be sent -> probably currently receiving external interference */
                    sendDoneGTS(AckLayerResponse::SEND_FAILED, msg);
                }

                // statistics
                this->numTxGtsFrames++;
            }
        } else {
            finalizeGTSTransmission();
        }
    }
}

void MessageDispatcher::handleGTSFrame(IDSMEMessage* msg) {
    DSME_ASSERT(currentACTElement != dsme.getMAC_PIB().macDSMEACT.end());

    numRxGtsFrames++;
    numUnusedRxGts--;

#if (ENABLE_SECURITY_ALL == 1)
    bool isAuthenticated;
    msg = DecryptFrame(msg, &isAuthenticated);
#endif

    if(currentACTElement->getSuperframeID() == dsme.getCurrentSuperframe() &&
       currentACTElement->getGTSlotID() == dsme.getCurrentSlot() - (dsme.getMAC_PIB().helper.getFinalCAPSlot(dsme.getCurrentSuperframe()) + 1)) {
        // According to 5.1.10.5.3
        currentACTElement->resetIdleCounter();
    }

    createDataIndication(msg);
}

void MessageDispatcher::onCSMASent(IDSMEMessage* msg, DataStatus::Data_Status status, uint8_t numBackoffs, uint8_t transmissionAttempts) {
    if(status == DataStatus::Data_Status::NO_ACK || status == DataStatus::Data_Status::SUCCESS) {
        if(msg->getHeader().isAckRequested() && !msg->getHeader().getDestAddr().isBroadcast()) {
            this->dsme.getPlatform().signalAckedTransmissionResult(status == DataStatus::Data_Status::SUCCESS, transmissionAttempts,
                                                                   msg->getHeader().getDestAddr());
        }
    }

    if(msg->getReceivedViaMCPS()) {
        mcps_sap::DATA_confirm_parameters params;
        params.msduHandle = msg;
        params.timestamp = 0; // TODO
        params.rangingReceived = false;
        params.status = status;
        params.numBackoffs = numBackoffs;
        params.gtsTX = false;
        this->dsme.getMCPS_SAP().getDATA().notify_confirm(params);
    } else {
        if(msg->getHeader().getFrameType() == IEEE802154eMACHeader::FrameType::COMMAND) {
            MACCommand cmd;
            cmd.decapsulateFrom(msg);

            LOG_DEBUG("cmdID " << (uint16_t)cmd.getCmdId());

            switch(cmd.getCmdId()) {
                case ASSOCIATION_REQUEST:
                case ASSOCIATION_RESPONSE:
                case DISASSOCIATION_NOTIFICATION:
                    this->dsme.getAssociationManager().onCSMASent(msg, cmd.getCmdId(), status, numBackoffs);
                    break;
                case DATA_REQUEST:
                case DSME_ASSOCIATION_REQUEST:
                case DSME_ASSOCIATION_RESPONSE:
                    DSME_ASSERT(false);
                    // TODO handle correctly
                    this->dsme.getPlatform().releaseMessage(msg);
                    break;
                case BEACON_REQUEST:
                case DSME_BEACON_ALLOCATION_NOTIFICATION:
                case DSME_BEACON_COLLISION_NOTIFICATION:
                    this->dsme.getBeaconManager().onCSMASent(msg, cmd.getCmdId(), status, numBackoffs);
                    break;
                case DSME_GTS_REQUEST:
                case DSME_GTS_REPLY:
                case DSME_GTS_NOTIFY:
                    this->dsme.getGTSManager().onCSMASent(msg, cmd.getCmdId(), status, numBackoffs);
                    break;
            }
        } else {
            this->dsme.getPlatform().releaseMessage(msg);
        }
    }
}

void MessageDispatcher::sendDoneGTS(enum AckLayerResponse response, IDSMEMessage* msg) {
    LOG_DEBUG("sendDoneGTS");

    DSME_ASSERT(lastSendGTSNeighbor != neighborQueue.end());
    DSME_ASSERT(msg == neighborQueue.front(lastSendGTSNeighbor));

    DSMEAllocationCounterTable& act = this->dsme.getMAC_PIB().macDSMEACT;
    DSME_ASSERT(this->currentACTElement != act.end());

    if(response != AckLayerResponse::NO_ACK_REQUESTED && response != AckLayerResponse::ACK_SUCCESSFUL) {
        currentACTElement->incrementIdleCounter();

        // not successful -> retry?
        if(msg->getRetryCounter() < dsme.getMAC_PIB().macMaxFrameRetries) {
            msg->increaseRetryCounter();
            finalizeGTSTransmission();
            LOG_DEBUG("sendDoneGTS - retry");
            return; // will stay at front of queue
        }
    }

    if(response == AckLayerResponse::ACK_FAILED || response == AckLayerResponse::ACK_SUCCESSFUL) {
        this->dsme.getPlatform().signalAckedTransmissionResult(response == AckLayerResponse::ACK_SUCCESSFUL, msg->getRetryCounter() + 1,
                                                               msg->getHeader().getDestAddr());
    }

    neighborQueue.popFront(lastSendGTSNeighbor);
    lastSendGTSNeighbor = neighborQueue.end();

    mcps_sap::DATA_confirm_parameters params;
    params.msduHandle = msg;
    params.timestamp = 0; // TODO
    params.rangingReceived = false;
    params.gtsTX = true;

    switch(response) {
        case AckLayerResponse::NO_ACK_REQUESTED:
        case AckLayerResponse::ACK_SUCCESSFUL:
            LOG_DEBUG("sendDoneGTS - success");
            params.status = DataStatus::SUCCESS;
            break;
        case AckLayerResponse::ACK_FAILED:
            DSME_ASSERT(this->currentACTElement != this->dsme.getMAC_PIB().macDSMEACT.end());
            currentACTElement->incrementIdleCounter();
            params.status = DataStatus::NO_ACK;
            break;
        case AckLayerResponse::SEND_FAILED:
            LOG_DEBUG("SEND_FAILED during GTS");
            DSME_ASSERT(this->currentACTElement != this->dsme.getMAC_PIB().macDSMEACT.end());
            currentACTElement->incrementIdleCounter();
            params.status = DataStatus::CHANNEL_ACCESS_FAILURE;
            break;
        case AckLayerResponse::SEND_ABORTED:
            LOG_DEBUG("SEND_ABORTED during GTS");
            params.status = DataStatus::TRANSACTION_EXPIRED;
            break;
        default:
            DSME_ASSERT(false);
    }

    params.numBackoffs = 0;
    this->dsme.getMCPS_SAP().getDATA().notify_confirm(params);
    finalizeGTSTransmission();
}

} /* namespace dsme */
