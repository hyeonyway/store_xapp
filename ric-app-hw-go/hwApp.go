/*
==================================================================================
  Copyright (c) 2024 Your Organization

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

   This source code is part of the near-RT RIC (RAN Intelligent Controller)
   platform project (RICP).
==================================================================================
*/

package main

import (
	"fmt"
	"time"

	"gerrit.o-ran-sc.org/r/ric-plt/xapp-frame/pkg/xapp"
)

type HWApp struct {
}

var (
	RIC_E2_RESET_REQ  = 12004
	E2_RESET_PAYLOAD  = `{"action":"terminate"}`
	e2NodeIDs         = []string{"gnb_208_099_00bc614e", "gnb_208_099_05397fb1"} // 리셋 메시지를 보낼 E2 Node 리스트
)

func (e *HWApp) sendE2Reset() {
	xapp.Logger.Info("Invoked method to send E2 Reset message")

	for _, e2NodeID := range e2NodeIDs {
		xapp.Logger.Info("Sending E2 Reset Request to E2 Node ID: %s", e2NodeID)

		// E2 Reset Request 메시지 생성
		payload := fmt.Sprintf(`{"action":"terminate","e2_node_id":"%s"}`, e2NodeID)
		rmrParams := &xapp.RMRParams{
			Mtype:     RIC_E2_RESET_REQ,
			Payload:   []byte(payload),
			PayloadLen: len(payload),
			Meid:      &xapp.RMRMeid{RanName: e2NodeID}, // 포인터 타입으로 설정
		}

		// RMR 메시지 전송
		success := xapp.Rmr.SendMsg(rmrParams)
		if success {
			xapp.Logger.Info("Successfully sent E2 Reset Request for E2 Node ID '%s'", e2NodeID)
		} else {
			xapp.Logger.Error("Failed to send E2 Reset Request for E2 Node ID '%s'", e2NodeID)
		}

		// 메시지 버퍼 해제
		xapp.Rmr.Free(rmrParams.Mbuf)
		rmrParams.Mbuf = nil
	}
}

// **주기적으로 E2 Reset 메시지를 전송하는 함수**
func (e *HWApp) startPeriodicE2Reset() {
	for {
		time.Sleep(30 * time.Second) // 30초마다 실행
		e.sendE2Reset()
	}
}

func (e *HWApp) ConfigChangeHandler(f string) {
	xapp.Logger.Info("Config file changed")
}

func (e *HWApp) xAppStartCB(d interface{}) {
	xapp.Logger.Info("xApp ready call back received")
}

func (e *HWApp) Consume(msg *xapp.RMRParams) (err error) {
	id := xapp.Rmr.GetRicMessageName(msg.Mtype)

	xapp.Logger.Info("Message received: name=%s meid=%s subId=%d txid=%s len=%d", id, msg.Meid.RanName, msg.SubId, msg.Xid, msg.PayloadLen)

	switch id {
	// E2 Reset 요청을 직접 처리 (필요하면 이 부분 활용 가능)
	case "RIC_E2_RESET_REQ":
		xapp.Logger.Info("Received E2 Reset Request message")

	default:
		xapp.Logger.Info("Unknown message type '%d', discarding", msg.Mtype)
	}

	defer func() {
		xapp.Rmr.Free(msg.Mbuf)
		msg.Mbuf = nil
	}()
	return nil
}

func (e *HWApp) Run() {
	// Set MDC
	xapp.Logger.SetMdc("HWApp", "0.0.1")

	// Set config change listener
	xapp.AddConfigChangeListener(e.ConfigChangeHandler)

	// Register callback after xApp ready
	xapp.SetReadyCB(e.xAppStartCB, true)

	// Start periodic E2 Reset 메시지 전송
	go e.startPeriodicE2Reset()

	// Read configuration from config file
	waitForSdl := xapp.Config.GetBool("db.waitForSdl")

	// Start xApp
	xapp.RunWithParams(e, waitForSdl)
}

func main() {
	hw := HWApp{}
	hw.Run()
}