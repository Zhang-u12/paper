import fastecdsa.curve as curve
from hashlib import sha256
from fastecdsa import ecdsa
import time

def ver_sig(signature,m,pid,vpk,t):
    # 检查时间t的有效性
    # DSRC协议里面的往返时间(单位毫秒)
    RTT=100
    # 1.先计算当前时间戳
    t1 = time.perf_counter()
    # 2.计算时间差值
    t2=t1-t
    # print('t2:',t2*1000)
    # 3.判断时间是否大于往返时间
    if((RTT-t2*1000)>0):
        # 计算接收到的消息的哈希值
        vpk_str = f'{vpk.x}{vpk.y}'
        message = m + pid + vpk_str + str(t)
        hashed_message = sha256(message.encode('utf-8')).digest()

        # 计算当前时间戳
        t0 = time.perf_counter()

        # 验证
        valid = ecdsa.verify(signature, hashed_message, vpk, curve.P256)

        # 获取当前时间戳
        end_time = time.perf_counter()

        # 计算代码执行时间（单位：毫秒）
        elapsed_time = (end_time - t0) * 1000
        print("验证签名的时间: ", elapsed_time, "milliseconds")
        if valid:
            return 'signature is valid!'

        else:
            return 'signature is invalid!'
    else:
        return 'signature is invalid!'