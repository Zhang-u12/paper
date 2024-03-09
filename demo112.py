import fastecdsa.curve as curve
import fastecdsa.keys as keys
from hashlib import sha256
from fastecdsa import ecdsa
import time
import demo111
import binascii

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
    print('pid为：',pid)
    # 将不是字符串的参数转为字符串
    # pid_str = pid.hex() # 字节==>字符
    pid_str = binascii.hexlify(pid).decode()
    vpk_str = f'{vpk.x}{vpk.y}'
    # print('vpk_str',vpk_str)
    sig,t1=sign(m,pid_str,vpk_str,vsk)
    print('签名为：',sig)
    print('签名的当前时间为：', t1)

