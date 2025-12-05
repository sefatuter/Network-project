import datetime
from logging import config, Logger, getLogger
import yaml
import context

class DetectionLogger():
    logger: Logger

    @staticmethod
    def setup_logger():
        global logger

        with open("config.yaml", "r") as f:
            config_file = yaml.safe_load(f)

        with open("handlers_config.yaml", "r") as hf:
            handlers_config = yaml.safe_load(hf)

        for name, conf in handlers_config.items():
            if name in context.active_handlers:
                config_file["handlers"][name] = conf
                config_file["loggers"]["mitm_defender"]["handlers"].append(name)

        if "file" in context.active_handlers:
            # Inject a real timestamp into the filename
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            context.log_file_name = f"events_{timestamp}.log"
            config_file["handlers"]["file"]["filename"] = context.log_file_name

        config.dictConfig(config_file)
        logger = getLogger("mitm_defender")

        # Detach handlers not in active_handlers
        for h in logger.handlers:
            if h.get_name() not in context.active_handlers:
                logger.removeHandler(h)

        logger.info("Logging system loaded!")
        
        return logger