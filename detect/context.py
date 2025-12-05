from logging import Logger

active_handlers: list[str] = []
interval: int = 5
gateway_ip: str = ""
original_mac: str = ""
mitm_logger: Logger = None
log_file_name: str = ""