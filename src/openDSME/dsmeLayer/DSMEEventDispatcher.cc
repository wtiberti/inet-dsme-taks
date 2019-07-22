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

#include "./DSMEEventDispatcher.h"

#include "../helper/DSMEAtomic.h"
#include "../mac_services/pib/MAC_PIB.h"
#include "../mac_services/pib/PIBHelper.h"
#include "./DSMELayer.h"
#include "./ackLayer/AckLayer.h"
#include "./capLayer/CAPLayer.h"

namespace dsme {

DSMEEventDispatcher::DSMEEventDispatcher(DSMELayer& dsme) : DSMETimerMultiplexer(this, NOW, TIMER), dsme(dsme) {
}

void DSMEEventDispatcher::initialize() {
    this->NOW.initialize(&(this->dsme.getPlatform()), &IDSMEPlatform::getSymbolCounter);
    this->TIMER.initialize(&(this->dsme.getPlatform()), &IDSMEPlatform::startTimer);

    DSMETimerMultiplexer::_initialize();
}

void DSMEEventDispatcher::reset() {
    _reset();
    return;
}

void DSMEEventDispatcher::timerInterrupt() {
    DSMETimerMultiplexer::_timerInterrupt();
}

/********** Event Handlers **********/

void DSMEEventDispatcher::firePreSlotTimer(int32_t lateness) {
    this->dsme.preSlotEvent();
}

void DSMEEventDispatcher::fireSlotTimer(int32_t lateness) {
    this->dsme.slotEvent(lateness);
}

void DSMEEventDispatcher::fireCSMATimer(int32_t lateness) {
    this->dsme.getCapLayer().dispatchTimerEvent();
}

void DSMEEventDispatcher::fireACKTimer(int32_t lateness) {
    this->dsme.getAckLayer().dispatchTimer();
}

/********** Setup Methods **********/

uint32_t DSMEEventDispatcher::setupSlotTimer(uint32_t lastSlotTime, uint8_t skippedSlots) {
    uint32_t symbols_per_slot = dsme.getMAC_PIB().helper.getSymbolsPerSlot();
    uint32_t next_slot_time = lastSlotTime + (1 + skippedSlots) * symbols_per_slot;

    DSME_ATOMIC_BLOCK {
        if(next_slot_time - PRE_EVENT_SHIFT <= NOW + 1) {
            next_slot_time += symbols_per_slot;
        }
        DSMETimerMultiplexer::_startTimer<NEXT_SLOT>(next_slot_time, &DSMEEventDispatcher::fireSlotTimer);
        DSMETimerMultiplexer::_startTimer<NEXT_PRE_SLOT>(next_slot_time - PRE_EVENT_SHIFT, &DSMEEventDispatcher::firePreSlotTimer);
        DSMETimerMultiplexer::_scheduleTimer();
    }

    return next_slot_time;
}

void DSMEEventDispatcher::setupCSMATimer(uint32_t absSymCnt) {
    DSME_ATOMIC_BLOCK {
        DSMETimerMultiplexer::_startTimer<CSMA_TIMER>(absSymCnt, &DSMEEventDispatcher::fireCSMATimer);
        DSMETimerMultiplexer::_scheduleTimer();
    }
    return;
}

void DSMEEventDispatcher::setupACKTimer() {
    DSME_ATOMIC_BLOCK {
        uint32_t ackTimeout = dsme.getMAC_PIB().helper.getAckWaitDuration() + NOW;
        DSMETimerMultiplexer::_startTimer<ACK_TIMER>(ackTimeout, &DSMEEventDispatcher::fireACKTimer);
        DSMETimerMultiplexer::_scheduleTimer();
    }
    return;
}

void DSMEEventDispatcher::stopACKTimer() {
    DSME_ATOMIC_BLOCK {
        DSMETimerMultiplexer::_stopTimer<ACK_TIMER>();
        DSMETimerMultiplexer::_scheduleTimer();
    }
    return;
}

} /* namespace dsme */
