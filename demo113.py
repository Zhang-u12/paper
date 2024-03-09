import binascii

import fastecdsa.curve as curve
from hashlib import sha256
from fastecdsa import ecdsa, keys
import time

from paper import demo111
from paper.demo112 import sign


def ver_sig(signature,m,pid,vpk,t):
    # 检查时间t的有效性
    # DSRC协议里面的往返时间(单位毫秒)
    RTT=100
    # 1.先计算当前时间戳
    t1 = time.perf_counter()
    # 2.计算时间差值
    t2=t1-t
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


if __name__ == '__main__':
    # 获取公私钥对
    vsk, vpk = keys.gen_keypair(curve.P256)
    # 假名的生成的测验
    w = 240  # 一天总的时间为w
    j = 10  # 每个时间段的长度

    # 两个用于生成假名的哈希值s1,s2(在Zq范围内随机获取一个随机数)
    s1 = keys.gen_private_key(curve.P256)
    s2 = keys.gen_private_key(curve.P256)
    k = keys.gen_private_key(curve.P256)

    m='this is a test message'
    pid=demo111.gener(s1, s2, vpk, j, w, k)
    # print('pid为：',pid)
    # 将不是字符串的参数转为字符串
    pid_str = binascii.hexlify(pid).decode()
    vpk_str = f'{vpk.x}{vpk.y}'
    # print('vpk_str',vpk_str)
    sig,t1=sign(m,pid_str,vpk_str,vsk)
    print('签名为：',sig)
    print('签名的时间为：',t1)
    result=ver_sig(sig,m,pid_str,vpk,t1)
    print('result:',result)
