import sys
import configparser

from pathlib import Path


def base_dir_path() -> Path:
    # 判断是否在打包环境中运行
    if getattr(sys, 'frozen', False):
        # 如果是打包环境(EXE)，使用sys.executable的位置
        application_path = Path(sys.executable).parent.absolute()
    else:
        # 如果是开发环境，使用__file__
        application_path = Path(__file__).parent.parent.absolute()
    return application_path

def get_config_ini() -> configparser.ConfigParser:
    config_path = base_dir_path().joinpath("rqsession", "config.ini")
    c = configparser.ConfigParser()
    c.read(config_path)
    return c
