# ==================================================================================
#
#       Copyright (c) 2025 Samsung Electronics Co., Ltd. All Rights Reserved.
#
# ==================================================================================
import requests
import struct
import random
import time
from os import getenv
from ricxappframe.xapp_frame import RMRXapp, rmr
from mdclogpy import Level
import ricxappframe.entities.rnib.nodeb_info_pb2 as pb_nbi
from .manager import *
from .handler import *
from .asn1 import OnosAsnProxy
from .utils.constants import Constants

MRC_SEND = None


class E2NodeTerminatorXApp:

    __XAPP_NAME = "e2node-terminator"
    __XAPP_VERSION = "0.0.1"
    __XAPP_NAMESPACE = "ricxapp"
    __PLT_NAMESPACE = "ricplt"
    __HTTP_PORT = 8080
    __RMR_PORT = 4560
    __XAPP_CONFIG_PATH = "/tmp/init/config-file.json"
    __CONFIG_PATH = "/ric/v1/config"

    def __init__(self):
        fake_sdl = getenv("USE_FAKE_SDL", False)
        self._rmr_xapp = RMRXapp(self._default_handler,
                                 config_handler=self._handle_config_change,
                                 rmr_port=self.__RMR_PORT,
                                 post_init=self._post_init,
                                 use_fake_sdl=bool(fake_sdl))

    def _post_init(self, rmr_xapp):
        """
        xApp 초기화 후 실행되는 함수
        """
        global MRC_SEND
        MRC_SEND = rmr.rmr_init(str(self.__RMR_PORT).encode(), rmr.RMR_MAX_RCV_BYTES, 0x00)
        while rmr.rmr_ready(MRC_SEND) == 0:
            time.sleep(1)
            rmr_xapp.logger.info("[Warning] Waiting for RMR to be ready...")


        rmr_xapp.logger.set_level(Level.INFO)
        rmr_xapp.logger.info("E2NodeTerminatorXApp.post_init :: post_init called")
        self.sdl_mgr = SdlManager(rmr_xapp)

        # ✅ xApp을 appmgr에 등록
        self._register_xapp(rmr_xapp)

        # ✅ RMR 메시지 전송 준비될 때까지 대기
        while not rmr_xapp.healthcheck():
            time.sleep(1)
            rmr_xapp.logger.info("[Warning] Waiting for RMR to be ready...")

        # ✅ 기존 E2 Node 연결 해제 요청 실행
        self._terminate_existing_connections(rmr_xapp)

    def _register_xapp(self, rmr_xapp):
        """
        ✅ appmgr에 xApp을 등록
        """
        url = f"http://service-{self.__PLT_NAMESPACE}-appmgr-http.{self.__PLT_NAMESPACE}:8080/ric/v1/register"

        try:
            with open(self.__XAPP_CONFIG_PATH, "r") as config_file:
                config_json_str = config_file.read()
        except IOError as e:
            rmr_xapp.logger.error(f"Failed to read xApp config file: {e}")
            return

        body = {
            "appName": self.__XAPP_NAME,
            "httpEndpoint": f"service-{self.__XAPP_NAMESPACE}-{self.__XAPP_NAME}-http.{self.__XAPP_NAMESPACE}:{self.__HTTP_PORT}",
            "rmrEndpoint": f"service-{self.__XAPP_NAMESPACE}-{self.__XAPP_NAME}-rmr.{self.__XAPP_NAMESPACE}:{self.__RMR_PORT}",
            "appInstanceName": self.__XAPP_NAME,
            "appVersion": self.__XAPP_VERSION,
            "configPath": self.__CONFIG_PATH,
            "config": config_json_str,
        }

        try:
            rmr_xapp.logger.info(f"Sending registration request to {url}")
            response = requests.post(url, json=body, timeout=5)
            rmr_xapp.logger.info(f"Registration response {response.status_code} {response.text}")
            if response.status_code == 201:
                rmr_xapp.logger.info("✅ xApp registration successful")
            else:
                rmr_xapp.logger.error(f"❌ xApp registration failed! Status Code: {response.status_code}, Response: {response.text}")

        except requests.exceptions.RequestException as e:
            rmr_xapp.logger.error(f"❌ xApp registration request failed: {e}")

    def _deregister_xapp(self, rmr_xapp):
        """
        ✅ appmgr에서 xApp 등록 해제
        """
        url = f"http://service-{self.__PLT_NAMESPACE}-appmgr-http.{self.__PLT_NAMESPACE}:8080/ric/v1/deregister"

        body = {
            "appName": self.__XAPP_NAME,
            "appInstanceName": f"{self.__XAPP_NAME}_{self.__XAPP_VERSION}",
        }

        try:
            rmr_xapp.logger.info(f"Sending deregistration request to {url}")
            response = requests.post(url, json=body, timeout=5)

            if response.status_code == 201:
                rmr_xapp.logger.info("✅ xApp deregistration successful")
            else:
                rmr_xapp.logger.error(f"❌ xApp deregistration failed! Status Code: {response.status_code}, Response: {response.text}")

        except requests.exceptions.RequestException as e:
            rmr_xapp.logger.error(f"❌ xApp deregistration request failed: {e}")

    def _terminate_existing_connections(self, rmr_xapp):
        """
        SDL에서 연결된 E2 Nodes를 가져와서 연결 해제 요청 전송
        """
        rmr_xapp.logger.info("Fetching connected E2 Nodes from SDL...")
        gnb_list = self.sdl_mgr.get_e2_node_ids()
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
        rmr_xapp.logger.info(f"Sending E2 Reset Request for E2 Node ID: {e2_node_id}")

        e2_request_id = random.randint(1, 999999)
        ran_function_id = self.sdl_mgr.get_ran_function_id(e2_node_id)
        if ran_function_id is None:
            rmr_xapp.logger.error(f"Failed to get RAN Function ID for {e2_node_id}")
            return

        payload = struct.pack(">II", e2_request_id, ran_function_id)

        # ✅ 디버깅 추가 (payload 값 확인)
        rmr_xapp.logger.info(f"[DEBUG] Payload Before Sending: {payload.hex()} (Length: {len(payload)})")

        # ✅ `MRC_SEND`을 사용하여 메시지 할당
        sbuf = rmr.rmr_alloc_msg(MRC_SEND, max(len(payload), 1), mtype=Constants.RIC_E2_RESET_REQ)
        if sbuf is None:
            rmr_xapp.logger.error("Failed to allocate RMR message buffer")
            return

        meid = b"mme_ar|10.98.211.42:38000"

        try:
            rmr.rmr_set_meid(sbuf, meid)
            rmr_xapp.logger.info(f"[DEBUG] MEID After Set: {rmr.rmr_get_meid(sbuf)}")
            rmr.set_payload_and_length(payload, sbuf)
            summary = rmr.message_summary(sbuf)
            rmr_xapp.logger.info(f"[DEBUG] before RMR Message Summary: {summary}")

            sbuf = rmr.rmr_send_msg(MRC_SEND, sbuf)
            summary = rmr.message_summary(sbuf)

            # ✅ 디버깅 추가 (Final RMR 상태 체크)
            rmr_xapp.logger.info(f"[DEBUG] Final RMR Message Summary: {summary}")

            if summary[rmr.RMR_MS_MSG_STATE] == rmr.RMR_OK:
                rmr_xapp.logger.info(f"✅ Successfully sent E2 Reset Request for {e2_node_id}")
            elif summary[rmr.RMR_MS_MSG_STATE] == rmr.RMR_ERR_NOENDPT:
                rmr_xapp.logger.error(f"❌ No endpoint found for {e2_node_id}. Check RTG configuration!")
            else:
                rmr_xapp.logger.error(f"❌ Failed to send E2 Reset Request. Error: {summary[rmr.RMR_MS_MSG_STATUS]}")

        except Exception as e:
            rmr_xapp.logger.error(f"Error while setting payload or sending message: {e}")

        finally:
            rmr.rmr_free_msg(sbuf)


    def _default_handler(self, rmr_xapp, summary, sbuf):
        """
        Default handler for RMR messages
        """

        msg_type = summary[rmr.RMR_MS_MSG_TYPE]

        rmr_xapp.logger.info("E2NodeTerminatorXApp.default_handler called for msg type = " +
                             str(summary[rmr.RMR_MS_MSG_TYPE]))
        rmr_xapp.rmr_free(sbuf)

    def _handle_config_change(self, rmr_xapp, config):
        """
        Handle configuration changes
        """
        rmr_xapp.logger.info(f"Configuration changed: {config}")
        rmr_xapp.config = config

    def createHandlers(self):
        """
        Function that creates all the handlers for RMR Messages
        """

        SubscriptionHandler(self._rmr_xapp, Constants.SUBSCRIPTION_REQ)

    def start(self, thread=False):
        """Start xApp"""
        self.createHandlers()
        self._rmr_xapp.run(thread)

    def stop(self):
        """Stop xApp & deregister"""
        self._deregister_xapp(self._rmr_xapp)
        self._rmr_xapp.stop()


if __name__ == "__main__":
    xapp = E2NodeTerminatorXApp()
    xapp.start()

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