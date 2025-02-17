import struct
import random
from ricxappframe.xapp_frame import rmr
from mdclogpy import Level
from ._BaseHandler import _BaseHandler
from ..utils.constants import Constants


class E2ResetHandler(_BaseHandler):
    """
    ✅ E2 RESET REQUEST 메시지를 처리하는 핸들러
    """

    def __init__(self, rmr_xapp):
        super().__init__(rmr_xapp, Constants.RIC_E2_RESET_REQ)
        self.rmr_xapp = rmr_xapp

    def send_e2_reset_request(self, e2_node_id, ran_function_id):
        """
        ✅ E2 Reset Request 메시지를 생성하여 RMR로 전송
        """
        self.rmr_xapp.logger.info(f"📤 Sending E2 Reset Request for E2 Node ID: {e2_node_id}")

        e2_request_id = random.randint(1, 999999)

        # ✅ E2 Reset 요청 패킷 생성 (ASN.1 Encoding 필요)
        payload = struct.pack(">II", e2_request_id, ran_function_id)

        # ✅ RMR 메시지 할당
        sbuf = rmr.rmr_alloc_msg(self.rmr_xapp._mrc, max(len(payload), 1), mtype=Constants.RIC_E2_RESET_REQ)
        if sbuf is None:
            self.rmr_xapp.logger.error("❌ Failed to allocate RMR message buffer")
            return False

        try:
            rmr.set_payload_and_length(payload, sbuf)

            # ✅ 메시지 전송
            result = rmr.rmr_send_msg(self.rmr_xapp._mrc, sbuf)
            if result:
                self.rmr_xapp.logger.info(f"✅ Successfully sent E2 Reset Request for E2 Node ID: {e2_node_id}")
            else:
                self.rmr_xapp.logger.error(f"❌ Failed to send E2 Reset Request for {e2_node_id}")
            return result

        except Exception as e:
            self.rmr_xapp.logger.error(f"❌ Error while setting payload or sending message: {e}")
            return False

        finally:
            rmr.rmr_free_msg(sbuf)