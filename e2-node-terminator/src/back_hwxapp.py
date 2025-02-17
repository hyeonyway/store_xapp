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

class Constants:
    RIC_E2_RESET_REQ = 12004  # ✅ E2 Reset Request Message Type
    RIC_E2_RESET_RESP = 12005  # ✅ E2 Reset Response Message Type

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
        rmr_xapp.logger.set_level(Level.INFO)
        rmr_xapp.logger.info("E2NodeTerminatorXApp.post_init :: post_init called")
        self.sdl_mgr = SdlManager(rmr_xapp)

        # ✅ xApp을 appmgr에 등록
        self._register_xapp(rmr_xapp)

        # ✅ RMR 메시지 전송 준비될 때까지 대기
        while rmr.rmr_ready(rmr_xapp.rmr) == 0:
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

        sbuf = rmr.rmr_alloc_msg(rmr_xapp._mrc, max(len(payload), 1), mtype=Constants.RIC_E2_RESET_REQ)
        if sbuf is None:
            rmr_xapp.logger.error("Failed to allocate RMR message buffer")
            return

        try:
            rmr.set_payload_and_length(payload, sbuf)
            result = rmr.rmr_send_msg(rmr_xapp._mrc, sbuf)
            if result:
                rmr_xapp.logger.info(f"✅ Successfully sent E2 Reset Request for {e2_node_id}")
            else:
                rmr_xapp.logger.error(f"❌ Failed to send E2 Reset Request for {e2_node_id}")
        except Exception as e:
            rmr_xapp.logger.error(f"Error while setting payload or sending message: {e}")
        finally:
            rmr.rmr_free_msg(sbuf)

    def start(self, thread=False):
        """Start xApp"""
        self._rmr_xapp.run(thread)

    def stop(self):
        """Stop xApp & deregister"""
        self._deregister_xapp(self._rmr_xapp)
        self._rmr_xapp.stop()

if __name__ == "__main__":
    xapp = E2NodeTerminatorXApp()
    xapp.start()