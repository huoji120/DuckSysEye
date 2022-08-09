import json
from tkinter.messagebox import NO
from sqlalchemy import create_engine
from sqlalchemy import Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base

import time
# 引入sqlalchemy中相关模块
from sqlalchemy import create_engine, MetaData
from sqlalchemy import Column, Integer, String, Table
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy import select, update, delete, values


g_engine = None
g_base = declarative_base()
g_metadata = None
g_rawdata_table = None
g_rawdata_table_ins = None
g_threat_table = None
g_threat_table_ins = None


class raw_log(g_base):
    __tablename__ = 'raw_log'
    # 定义各字段
    id = Column(Integer, primary_key=True)
    # 主机ip
    host = Column(String)
    # 原始字段
    action = Column(String)
    # 原始字段
    data = Column(String)
    # 时间戳
    timestamp = Column(String)
    hit = Column(String)
    score = Column(Integer)
    chain_hash = Column(String)
    type = Column(Integer)

    def __str__(self):
        return self.id


class threat_log(g_base):
    __tablename__ = 'threat_log'
    # 定义各字段
    id = Column(Integer, primary_key=True)
    # 主机ip
    host = Column(String)
    # 进程链hash,其他的为000000
    process_chain_hash = Column(String)
    # type
    type = Column(Integer)
    # 分数
    risk_score = Column(Integer)
    # 命中的规则
    hit_rule = Column(String)
    # json字段
    data = Column(String)
    # 时间戳
    timestamp = Column(String)
    # is end
    is_end = Column(Integer)
    # start process
    start_process_info = Column(String)
    # handle type
    handle_type = Column(Integer)

    def __str__(self):
        return self.id


def init():
    global g_engine
    global g_base
    global g_metadata
    global g_rawdata_table
    global g_rawdata_table_ins
    global g_threat_table
    global g_threat_table_ins

    g_engine = create_engine(
        'sqlite:///syseye.db?check_same_thread=False', echo=False)
    g_base.metadata.create_all(g_engine)
    g_metadata = MetaData(g_engine)
    g_rawdata_table = Table('raw_log', g_metadata, autoload=True)
    g_rawdata_table_ins = g_rawdata_table.insert()

    g_threat_table = Table('threat_log', g_metadata, autoload=True)
    g_threat_table_ins = g_threat_table.insert()


def push_raw(host, log, rule_hit_name, score, chain_hash, type):
    global g_engine
    global g_rawdata_table
    global g_rawdata_table_ins
    timestamp = str(int(round(time.time() * 1000)))
    ins = g_rawdata_table_ins.values(host=host,
                                     action=log['Action'],
                                     data=json.dumps(log['Data']), timestamp=timestamp, hit=rule_hit_name, score=score, chain_hash=chain_hash, type=type)
    # 连接引擎
    conn = g_engine.connect()
    # 执行语句
    result = conn.execute(ins)
    return result


def select_threat_by_chain_id(host, process_chain_hash, type):
    global g_threat_table
    sql_session = sessionmaker(bind=g_engine)
    threat = sql_session().query(g_threat_table).filter_by(
        host=host, process_chain_hash=process_chain_hash, type=type).all()
    sql_session().close()
    return threat


def update_threat_log(host, risk_score, hit_rule_json, process_chain_hash, raw_json, type, is_end):
    global g_threat_table
    global g_engine
    conn = g_engine.connect()
    update = g_threat_table.update().values(risk_score=risk_score,
                                            hit_rule=hit_rule_json, data=raw_json, is_end=int(is_end)).where(g_threat_table.columns.host == host, g_threat_table.columns.process_chain_hash == process_chain_hash, g_threat_table.columns.type == type)
    result = conn.execute(update)
    return result


def handle_threat_log(threat_id, handle_type):
    global g_threat_table
    global g_engine
    conn = g_engine.connect()
    update = g_threat_table.update().values(handle_type=handle_type, is_end=1).where(
        g_threat_table.columns.id == int(threat_id))
    result = conn.execute(update)
    return result


def delete_threat(threat_id):
    global g_threat_table
    global g_engine
    conn = g_engine.connect()
    result = conn.execute(delete(g_threat_table).where(
        g_threat_table.columns.id == int(threat_id)))
    return result


def query_one_threat(threat_id):
    global g_threat_table
    sql_session = sessionmaker(bind=g_engine)
    threat = sql_session().query(g_threat_table).filter_by(
        id=threat_id).first()
    sql_session().close()
    return threat


def query_all_threat_log(query_type):
    global g_threat_table
    sql_session = sessionmaker(bind=g_engine)
    if int(query_type) == -1:
        threat = sql_session().query(g_threat_table).with_entities(threat_log.host, threat_log.process_chain_hash,
                                                                   threat_log.hit_rule, threat_log.timestamp, threat_log.type, threat_log.risk_score, threat_log.id, threat_log.is_end, threat_log.start_process_info, threat_log.handle_type).all()
    else:
        threat = sql_session().query(g_threat_table).with_entities(threat_log.host, threat_log.process_chain_hash,
                                                                   threat_log.hit_rule, threat_log.timestamp, threat_log.type, threat_log.risk_score, threat_log.id, threat_log.is_end, threat_log.start_process_info, threat_log.handle_type).filter_by(handle_type=query_type).all()
    sql_session().close()
    return threat


def push_threat_log(host, risk_score, hit_rule_json, process_chain_hash, raw_json, type, start_process_info):
    global g_engine
    global g_threat_table
    global g_threat_table_ins
    ins = g_threat_table_ins.values(
        host=host, risk_score=risk_score, process_chain_hash=process_chain_hash, hit_rule=hit_rule_json, type=type, data=raw_json, timestamp=str(int(round(time.time() * 1000))), is_end=0, start_process_info=start_process_info, handle_type=0)
    # 连接引擎
    conn = g_engine.connect()
    # 执行语句
    result = conn.execute(ins)
    # print(raw_json)
    return result
