# ==================================================================================
#
#       Copyright (c) 2020 Samsung Electronics Co., Ltd. All Rights Reserved.
#
# ==================================================================================
import requests
import struct
from os import getenv
from ricxappframe.xapp_frame import RMRXapp, rmr
from mdclogpy import Level
import ricxappframe.entities.rnib.nodeb_info_pb2 as pb_nbi
import random  # ✅ E2 Request ID 생성을 위해 추가
import threading
import time

class Constants:
    RIC_E2_RESET_REQ = 12004  # ✅ E2 Reset Request Message Type
    RIC_E2_RESET_RESP = 12005  # ✅ E2 Reset Response Message Type


class E2NodeTerminatorXApp:

    __XAPP_NAME = "e2node-terminator"
    __XAPP_VERSION = "0.0.1"
    __RMR_PORT = 4560

    def __init__(self):
        fake_sdl = getenv("USE_FAKE_SDL", False)
        self._rmr_xapp = RMRXapp(self._default_handler,
                                 config_handler=self._handle_config_change,
                                 rmr_port=self.__RMR_PORT,
                                 post_init=self._post_init,
                                 use_fake_sdl=bool(fake_sdl))

        self._running = False
        self._timer = None

    def _post_init(self, rmr_xapp):
        """
        xApp 초기화 후 실행되는 함수
        """
        rmr_xapp.logger.set_level(Level.INFO)
        rmr_xapp.logger.info("E2NodeTerminatorXApp.post_init :: post_init called")
        self.sdl_mgr = SdlManager(rmr_xapp)
        self._running = True
        # self._terminate_existing_connections(rmr_xapp)
        self._start_sending_messages(rmr_xapp)

    def _start_sending_messages(self, rmr_xapp):
        if not self._running:
            return

        gnb_list = self.sdl_mgr.get_e2_node_ids()  # ✅ SDL에서 E2 Node ID 목록 가져오기
        if not gnb_list:
            rmr_xapp.logger.info("No connected E2 Nodes found.")
        else:
            for e2_node_id in gnb_list:
                rmr_xapp.logger.info(f"Found E2 Node ID: {e2_node_id}")
                self._send_e2_reset_request(rmr_xapp, e2_node_id)

        # ✅ 1초마다 `_start_sending_messages()` 호출
        self._timer = threading.Timer(1.0, self._start_sending_messages, [rmr_xapp])
        self._timer.start()

    def _terminate_existing_connections(self, rmr_xapp):
        """
        SDL에서 연결된 E2 Nodes를 가져와서 연결 해제 요청 전송
        """
        rmr_xapp.logger.info("Fetching connected E2 Nodes from SDL...")
        gnb_list = self.sdl_mgr.get_e2_node_ids()  # ✅ SDL에서 E2 Node ID 목록 가져오기
        if not gnb_list:
            rmr_xapp.logger.info("No connected E2 Nodes found.")
            return

        for e2_node_id in gnb_list:
            rmr_xapp.logger.info(f"Found E2 Node ID: {e2_node_id}")
            self._send_e2_reset_request(rmr_xapp, e2_node_id)

    def _send_e2_reset_request(self, rmr_xapp, e2_node_id):
        """
        ✅ E2 RESET REQUEST 메시지를 생성하고 전송
        """
        rmr_xapp.logger.info(f"Preparing E2 Reset Request for E2 Node ID: {e2_node_id}")

        # ✅ E2 Request ID 생성 (랜덤 정수 값)
        e2_request_id = random.randint(1, 999999)

        # ✅ E2 Node의 상세 정보 가져오기
        node_info = self.sdl_mgr.get_nodeb_info(e2_node_id)

        if node_info:
            # ✅ nodeb_info 모든 필드 출력
            rmr_xapp.logger.info(f"NodeB Info for {e2_node_id}: {node_info}")

            # ✅ 목적지 IP와 Port 설정 (associated_e2t_instance_address 사용)
            if node_info.associated_e2t_instance_address:
                dst_ip, dst_port = node_info.associated_e2t_instance_address.split(":")  # ✅ IP와 Port 분리
            else:
                dst_ip, dst_port = "Unknown", "Unknown"

            # ✅ RAN Function ID 가져오기
            ran_function_id = self.sdl_mgr.get_ran_function_id(e2_node_id)
            if ran_function_id is None:
                rmr_xapp.logger.error(f"Failed to get RAN Function ID for {e2_node_id}")
                return

            # ✅ 로그 출력: 목적지 IP와 Port 포함
            rmr_xapp.logger.info(f"Sending E2 Reset Request to {dst_ip}:{dst_port} for E2 Node ID: {e2_node_id}")

            # ✅ E2 RESET 메시지의 payload (ASN.1 Encoding 필요)
            payload = struct.pack(">II", e2_request_id, ran_function_id)

            # ✅ RMR 메시지 할당
            sbuf = rmr.rmr_alloc_msg(rmr_xapp._mrc, max(len(payload), 1), mtype=Constants.RIC_E2_RESET_REQ)
            if sbuf is None:
                rmr_xapp.logger.error("Failed to allocate RMR message buffer")
                return

            try:
                # ✅ payload 설정
                rmr.set_payload_and_length(payload, sbuf)

                # ✅ 메시지 전송
                result = rmr.rmr_send_msg(rmr_xapp._mrc, sbuf)
                if result:
                    rmr_xapp.logger.info(f"Successfully sent E2 Reset Request to {dst_ip}:{dst_port} for E2 Node ID: {e2_node_id}")
                else:
                    rmr_xapp.logger.error(f"Failed to send E2 Reset Request to {dst_ip}:{dst_port} for E2 Node ID: {e2_node_id}")

            except Exception as e:
                rmr_xapp.logger.error(f"Error while setting payload or sending message: {e}")

            finally:
                rmr.rmr_free_msg(sbuf)
        else:
            rmr_xapp.logger.error(f"Failed to fetch NodeB Info for {e2_node_id}")

    def _default_handler(self, rmr_xapp, summary, sbuf):
        """
        Default handler for RMR messages
        """
        rmr_xapp.logger.info("E2NodeTerminatorXApp.default_handler called for msg type = " +
                             str(summary[rmr.RMR_MS_MSG_TYPE]))
        rmr_xapp.rmr_free(sbuf)

    def _handle_config_change(self, rmr_xapp, config):
        """
        Handle configuration changes
        """
        rmr_xapp.logger.info(f"Configuration changed: {config}")
        rmr_xapp.config = config

    def start(self, thread=False):
        """
        Start the xApp
        """
        self._rmr_xapp.run(thread)

    def stop(self):
        """
        Stop the xApp
        """
        self._running = False
        if self._teimr:
            self._timer.cancel()
            self._timer = None
        self._rmr_xapp.stop()


class SdlManager:
    def __init__(self, rmr_xapp):
        self.rmr_xapp = rmr_xapp  # ✅ SDL 접근을 위해 rmr_xapp 사용

    def get_e2_node_ids(self):
        """
        ✅ SDL에서 현재 연결된 E2 Node ID 목록 조회
        """
        try:
            gnb_list = self.rmr_xapp.get_list_gnb_ids()
            if not gnb_list:
                self.rmr_xapp.logger.info("No connected E2 Nodes found.")
                return []
            return [gnb.inventory_name for gnb in gnb_list]

        except Exception as e:
            self.rmr_xapp.logger.error(f"Error fetching E2 Node IDs from SDL: {e}")
            return []

    def get_ran_function_id(self, e2_node_id):
        """
        ✅ 특정 E2 Node의 RAN Function ID 조회
        """
        try:
            node_info = self.get_nodeb_info(e2_node_id)  # ✅ 변경된 함수 사용
            if node_info and node_info.HasField("gnb"):
                return node_info.gnb.ran_functions[0].ran_function_id
            return None
        except Exception as e:
            self.rmr_xapp.logger.error(f"Error fetching RAN Function ID: {e}")
            return None

    def get_nodeb_info(self, e2_node_id):
        """
        ✅ SDL에서 E2 Node 정보를 가져오기 (RAN:<E2_NODE_ID> 키로 저장됨)
        """
        try:
            nodeb_info_bytes = self.rmr_xapp.sdl.get("e2Manager", f"RAN:{e2_node_id}", usemsgpack=False)  # ✅ `self.sdl_mgr` 대신 `self.rmr_xapp.sdl` 사용
            if nodeb_info_bytes:
                nodeb_info = pb_nbi.NodebInfo()  # ✅ Protobuf NodebInfo 객체
                nodeb_info.ParseFromString(nodeb_info_bytes)  # ✅ 바이너리 데이터를 Protobuf 객체로 변환
                return nodeb_info
            return None
        except Exception as e:
            self.rmr_xapp.logger.error(f"Error fetching NodeB info: {e}")
            return None