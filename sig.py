import fastecdsa.curve as curve
from hashlib import sha256
from fastecdsa import ecdsa
import time


def sign(m,pid,vpk,vsk):

    # 计算当前时间
    t1=time.perf_counter()
    # 将时间转为字符串类型
    t1_str=str(t1)
    # 消息(包括消息本身，车辆的假名，车辆的公钥，当前时间戳)
    message=m+pid+vpk+t1_str
    # print('message:',message)
    # 计算消息的哈希
    hashed_message=sha256(message.encode('utf-8')).digest()
    # 对消息进行签名
    signature =ecdsa.sign(hashed_message, vsk, curve.P256)
    # 获取当前时间戳
    t2 = time.perf_counter()

    # 计算代码执行时间（单位：毫秒）
    elapsed_time = (t2 - t1) * 1000
    print("签名所花的时间: ", elapsed_time, "milliseconds")
    return signature,t1