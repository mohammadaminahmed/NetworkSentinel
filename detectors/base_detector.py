class BaseDetector:
    def __init__(self, name: str, alert_manager):
        self.name = name
        self.alert_manager = alert_manager

    def process(self, packet: bytes):
        raise NotImplementedError("Must implement process method")
