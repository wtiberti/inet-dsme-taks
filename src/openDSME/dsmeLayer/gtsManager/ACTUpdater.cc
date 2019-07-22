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

#include "./ACTUpdater.h"

#include "../../../dsme_platform.h"
#include "../../mac_services/dataStructures/DSMESABSpecification.h"
#include "../../mac_services/pib/MAC_PIB.h"
#include "../DSMELayer.h"
#include "../messages/GTSManagement.h"

#define LOG_ACT(x) LOG_DEBUG("ACTUpdater - " << x << " 0x" << HEXOUT << deviceAddr << DECOUT);

namespace dsme {

ACTUpdater::ACTUpdater(DSMELayer& dsme) : dsme(dsme) {
}

void ACTUpdater::requestAccessFailure(DSMESABSpecification& sabSpec, GTSManagement& management, uint16_t deviceAddr) {
    LOG_ACT("requestAccessFailure");
    // No action required
}

void ACTUpdater::requestNoAck(DSMESABSpecification& sabSpec, GTSManagement& management, uint16_t deviceAddr) {
    LOG_ACT("requestNoAck");
    // No action required
}

void ACTUpdater::responseTimeout(DSMESABSpecification& sabSpec, GTSManagement& management, uint16_t deviceAddr) {
    LOG_ACT("responseTimeout");
    // No action required
}

void ACTUpdater::approvalQueued(DSMESABSpecification& sabSpec, GTSManagement& management, uint16_t deviceAddr, uint16_t channelOffset) {
    LOG_DEBUG("ACTUpdater - approvavQueued");
    if(management.type == ManagementType::ALLOCATION) {
        bool useChannelOffset = dsme.getMAC_PIB().macChannelDiversityMode == Channel_Diversity_Mode::CHANNEL_HOPPING;
        this->dsme.getMAC_PIB().macDSMEACT.setACTState(sabSpec, ACTState::UNCONFIRMED, invert(management.direction), deviceAddr, channelOffset,
                                                       useChannelOffset, [](ACTState b) { return b != ACTState::INVALID; });
    }
}

void ACTUpdater::approvalReceived(DSMESABSpecification& sabSpec, GTSManagement& management, uint16_t deviceAddr, uint16_t channelOffset) {
    LOG_ACT("approvalReceived");
    if(management.type == ManagementType::ALLOCATION) {
        bool useChannelOffset = dsme.getMAC_PIB().macChannelDiversityMode == Channel_Diversity_Mode::CHANNEL_HOPPING;
        this->dsme.getMAC_PIB().macDSMEACT.setACTState(sabSpec, ACTState::UNCONFIRMED, management.direction, deviceAddr, channelOffset, useChannelOffset,
                                                       [](ACTState b) { return b != ACTState::INVALID; });
    }
}

void ACTUpdater::disapproved(DSMESABSpecification& sabSpec, GTSManagement& management, uint16_t deviceAddr, uint16_t channelOffset) {
    LOG_ACT("disapproved");
    if(management.type == ManagementType::DEALLOCATION) {
        DSME_ASSERT(sabSpec.getSubBlock().count(true) > 0);

        if(management.status == GTSStatus::DENIED) {
            this->dsme.getMAC_PIB().macDSMEACT.setACTStateIfExists(sabSpec, ACTState::REMOVED,
                                                                   channelOffset); // TODO: was INVALID before, can lead to endless cycles
        } else {
            // TODO probably was not added before, maybe an "UNCONFIRMED" is required though?
            this->dsme.getMAC_PIB().macDSMEACT.setACTStateIfExists(sabSpec, ACTState::REMOVED, channelOffset);
        }
    } else {
        // No action required
    }
}

void ACTUpdater::notifyAccessFailure(DSMESABSpecification& sabSpec, GTSManagement& management, uint16_t deviceAddr) {
    LOG_ACT("notifyAccessFailure");
    if(management.type == ManagementType::ALLOCATION) {
        // This is not handled by the standard, but improves the consistency
        // The sender of the notify is also the requester, so do not invert the direction
        this->dsme.getMAC_PIB().macDSMEACT.setACTState(sabSpec, ACTState::INVALID, management.direction, deviceAddr, 0, false);
    } else {
        // No action required
    }
}

void ACTUpdater::notifyDelivered(DSMESABSpecification& sabSpec, GTSManagement& management, uint16_t deviceAddr, uint16_t channelOffset) {
    LOG_ACT("notifyDelivered");
    if(management.type == ManagementType::ALLOCATION) {
        // The sender of the notify is also the requester, so do not invert the direction
        bool useChannelOffset = (dsme.getMAC_PIB().macChannelDiversityMode == Channel_Diversity_Mode::CHANNEL_HOPPING);
        this->dsme.getMAC_PIB().macDSMEACT.setACTState(sabSpec, ACTState::VALID, management.direction, deviceAddr, channelOffset, useChannelOffset,
                                                       [](ACTElement e) { return e.getState() != ACTState::INVALID; });
    } else if(management.type == ManagementType::DEALLOCATION) {
        // The sender of the notify is also the requester, so do not invert the direction
        this->dsme.getMAC_PIB().macDSMEACT.setACTState(sabSpec, ACTState::REMOVED, management.direction, deviceAddr, 0, false, true);
    }
}

void ACTUpdater::approvalDelivered(DSMESABSpecification& sabSpec, GTSManagement& management, uint16_t deviceAddr, uint16_t channelOffset) {
    LOG_ACT("approvalDelivered");
    if(management.type == ManagementType::ALLOCATION) {
        // This is not handled by the standard, but improves the consistency
        bool useChannelOffset = (dsme.getMAC_PIB().macChannelDiversityMode == Channel_Diversity_Mode::CHANNEL_HOPPING);
        this->dsme.getMAC_PIB().macDSMEACT.setACTState(sabSpec, ACTState::UNCONFIRMED, invert(management.direction), deviceAddr, channelOffset,
                                                       useChannelOffset);
    } else if(management.type == ManagementType::DEALLOCATION) {
        this->dsme.getMAC_PIB().macDSMEACT.setACTState(sabSpec, ACTState::UNCONFIRMED, invert(management.direction), deviceAddr, 0, false);
    } else {
        // No action required
    }
}

void ACTUpdater::approvalAccessFailure(DSMESABSpecification& sabSpec, GTSManagement& management, uint16_t deviceAddr) {
    LOG_ACT("approvalAccessFailure");
    if(management.type == ManagementType::DEALLOCATION) {
        // This is not handled by the standard, but improves the consistency
        this->dsme.getMAC_PIB().macDSMEACT.setACTState(sabSpec, ACTState::INVALID, invert(management.direction), deviceAddr, 0, false);
    } else {
        // No action required
    }
}

void ACTUpdater::notifyTimeout(DSMESABSpecification& sabSpec, GTSManagement& management, uint16_t deviceAddr, uint16_t channelOffset) {
    LOG_ACT("notifyTimeout");
    // This is not handled by the standard, but improves the consistency
    this->dsme.getMAC_PIB().macDSMEACT.setACTState(sabSpec, ACTState::INVALID, invert(management.direction), deviceAddr, channelOffset, false);
}

void ACTUpdater::notifyReceived(DSMESABSpecification& sabSpec, GTSManagement& management, uint16_t deviceAddr, uint16_t channelOffset) {
    LOG_ACT("notifyReceived");
    if(management.type == ManagementType::ALLOCATION) {
        // The receiver of the notify is not the requester, so invert the direction
        bool useChannelOffset = (dsme.getMAC_PIB().macChannelDiversityMode == Channel_Diversity_Mode::CHANNEL_HOPPING);
        this->dsme.getMAC_PIB().macDSMEACT.setACTState(sabSpec, ACTState::VALID, invert(management.direction), deviceAddr, channelOffset, useChannelOffset,
                                                       [](ACTElement e) { return e.getState() != ACTState::INVALID; });
    } else if(management.type == ManagementType::DEALLOCATION) {
        this->dsme.getMAC_PIB().macDSMEACT.setACTState(sabSpec, ACTState::REMOVED, invert(management.direction), deviceAddr, 0, false);
    }
}

void ACTUpdater::disapprovalAccessFailure(DSMESABSpecification& sabSpec, GTSManagement& management, uint16_t deviceAddr) {
    LOG_ACT("disapprovalAccessFailure");
    // No action required
}

void ACTUpdater::disapprovalNoAck(DSMESABSpecification& sabSpec, GTSManagement& management, uint16_t deviceAddr) {
    LOG_ACT("disapprovalNoAck");
    // No action required
}

void ACTUpdater::disapprovalDelivered(DSMESABSpecification& sabSpec, GTSManagement& management, uint16_t deviceAddr) {
    LOG_ACT("disapprovalDelivered");
    // No action required
}

void ACTUpdater::duplicateAllocation(DSMESABSpecification& sabSpec, uint16_t channelOffset) {
    uint16_t deviceAddr = -1;
    LOG_ACT("duplicateAllocation");
    this->dsme.getMAC_PIB().macDSMEACT.setACTStateIfExists(sabSpec, ACTState::INVALID, channelOffset);
}

Direction ACTUpdater::invert(Direction direction) {
    // Invert the direction since the direction is from requesting device
    Direction dir = Direction::TX;
    if(direction == Direction::TX) {
        dir = Direction::RX;
    }
    return dir;
}

} /* namespace dsme */
