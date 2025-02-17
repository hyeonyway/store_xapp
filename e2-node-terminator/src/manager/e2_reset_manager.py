from ..handler.e2_reset_handler import E2ResetHandler
from .SdlManager import SdlManager


class E2ResetManager:
    """
    ✅ E2 RESET 요청을 관리하는 Manager 클래스
    """

    def __init__(self, rmr_xapp):
        self.rmr_xapp = rmr_xapp
        self.sdl_manager = SdlManager(rmr_xapp)
        self.e2_reset_handler = E2ResetHandler(rmr_xapp)

    def send_reset_to_all_gnbs(self):
        """
        ✅ 연결된 모든 gNB에 E2 Reset Request 전송
        """
        gnb_list = self.sdl_manager.get_gnb_list()
        if not gnb_list:
            self.rmr_xapp.logger.info("⚠ No connected gNBs found.")
            return

        for gnb in gnb_list:
            e2_node_id = gnb.inventory_name
            ran_function_id = self.sdl_manager.get_ran_function_id(e2_node_id)
            if ran_function_id:
                self.e2_reset_handler.send_e2_reset_request(e2_node_id, ran_function_id)
            else:
                self.rmr_xapp.logger.error(f"❌ Failed to retrieve RAN Function ID for {e2_node_id}")