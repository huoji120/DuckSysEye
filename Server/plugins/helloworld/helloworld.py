import global_vars
import yara
import glob
from pathlib import Path

rm_plugs_config = {
    "enable": False,
    "author": "huoji",
    "description": "hello world插件示例",
    "version": "0.0.1",
}


def process_terminal(current_process, host, raw_log_data, json_log_data):
    print('[helloworld plugin] rule new process create')


def rule_new_process_create(current_process, host, raw_log_data, json_log_data):
    print('[helloworld plugin] rule new process create')


def rule_new_process_action(current_process, host, raw_log_data, json_log_data):
    print('[helloworld plugin] rule new process action')


def rule_init():
    print('[helloworld plugin] rule init')


def plugin_init():
    print('[helloworld plugin] plugin init')
