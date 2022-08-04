import json
from pickle import TRUE
import time

from sqlalchemy import false
import process
import rule
import sql
import global_vars
import config


def process_log(host, json_log, raw_log):
    log = json_log['data']
    had_threat = global_vars.THREAT_TYPE_NONE
    current_process: process.Process = None
    rule_hit_name = ''
    score = 0
    chain_hash = ''

    if json_log['action'] == 'processcreate':
        pid = log['processid']
        ppid = log['parentprocessid']
        path = log['image']
        params = log['commandline']
        user = log['user']
        hash = log['hashes'].split(',')[0].split('=')[1]

        parent_pid = log['parentprocessid']
        parent_ppid = parent_pid
        parent_path = log['parentimage']
        parent_params = log['parentcommandline']
        parent_user = log['parentuser']
        create_time = int(round(time.time() * 1000))

        if path in process.skip_process_path or path in process.skip_process_path:
            return
        parent_process: process.Process = process.get_process_by_pid(ppid)
        score, rule_hit_name = rule.calc_score_in_create_process(log)
        if hash in process.skip_md5:
            return
        if parent_process is None or parent_path in process.root_process_path:
            # build a process
            parent_process = process.Process(
                parent_pid, parent_ppid, parent_path, parent_params, create_time - 1, "None", parent_user, host)
            child = process.Process(
                pid, ppid, path, params, create_time, hash, parent_user, host)
            chain = process.create_chain(parent_process)
            chain.add_process(child, parent_pid)
            current_process = child
            if score > 0:
                child.set_score(score, rule_hit_name)
                had_threat = global_vars.THREAT_TYPE_PROCESS
        else:
            child = process.Process(
                pid, ppid, path, params, create_time, hash, user, host)
            parent_process.chain.add_process(child, ppid)
            current_process = child
            if score > 0:
                child.set_score(score, rule_hit_name)
                had_threat = global_vars.THREAT_TYPE_PROCESS
    elif json_log['action'] == 'processterminal':
        pid = log['processid']
        current_process = process.get_process_by_pid(pid)
        if current_process is not None:
            current_process.active = False
            current_process.chain.terminate_count += 1
            if current_process.chain.terminate_count >= (current_process.chain.active_count - 1):
                current_process.chain.active = False
                print('进程链已经结束')
                if current_process.chain.risk_score >= config.MAX_THREAT_SCORE:
                    sql.update_threat_log(host, current_process.chain.risk_score,
                                          json.dumps(current_process.chain.operationlist), current_process.chain.hash, current_process.chain.get_json(), global_vars.THREAT_TYPE_PROCESS, True)
                process.g_ProcessChainList.remove(current_process.chain)
    elif 'processid' in log:
        current_process = process.get_process_by_pid(
            log['processid'])
        if current_process is not None:
            log['action'] = json_log['action']
            score, rule_hit_name = rule.calc_score_in_action(log)
            print(log, score, rule_hit_name)
            if score > 0:
                current_process.set_score(score, rule_hit_name)
                had_threat = global_vars.THREAT_TYPE_PROCESS

    if current_process is not None:
        if current_process.chain.risk_score >= config.MAX_THREAT_SCORE:
            if had_threat == global_vars.THREAT_TYPE_PROCESS:
                current_process.chain.update_process_tree()
                threat = sql.select_threat_by_chain_id(
                    host, current_process.chain.hash, global_vars.THREAT_TYPE_PROCESS)
                if len(threat) == 0:
                    process_info: process.Process = None

                    if len(current_process.chain.process_list) > 1:
                        process_info = current_process.chain.process_list[1]
                    else:
                        process_info = current_process
                    info_save_data = {'path': process_info.path, 'hash': process_info.md5, 'params': process_info.params,
                                      'user': process_info.user, 'create_time': process_info.time}
                    sql.push_threat_log(host, current_process.chain.risk_score,
                                        json.dumps(current_process.chain.operationlist), current_process.chain.hash, current_process.chain.get_json(), global_vars.THREAT_TYPE_PROCESS, json.dumps(info_save_data))
                else:
                    sql.update_threat_log(host, current_process.chain.risk_score,
                                          json.dumps(current_process.chain.operationlist), current_process.chain.hash, current_process.chain.get_json(), global_vars.THREAT_TYPE_PROCESS, current_process.chain.active == False)
    if current_process is not None:
        chain_hash = current_process.chain.hash
    sql.push_raw(host, json.loads(raw_log), rule_hit_name,
                 score, chain_hash, had_threat)

    '''
    for iter in process.g_ProcessChainList:
        item: process.Process = iter
        if item.risk_score >= config.MAX_THREAT_SCORE:
            item.print_process()
    '''
