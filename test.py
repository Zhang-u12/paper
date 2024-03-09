import binascii
import fastecdsa.curve as curve
import fastecdsa.keys as keys
import ver_sig
from paper import demo111
from paper.demo112 import sign

if __name__ == '__main__':
    # 获取公私钥对
    vsk, vpk = keys.gen_keypair(curve.P256)
    # 假名的生成的测验
    w = 24  # 一天总的时间为w
    j = 1 # 每个时间段的长度

    # 两个用于生成假名的哈希值s1,s2(在Zq范围内随机获取一个随机数)
    s1 = keys.gen_private_key(curve.P256)
    s2 = keys.gen_private_key(curve.P256)
    k = keys.gen_private_key(curve.P256)

    m='this is a test message'
    pid=demo111.gener(s1, s2, vpk, j, w, k)
    # 将不是字符串的参数转为字符串
    pid_str = binascii.hexlify(pid).decode()
    vpk_str = f'{vpk.x}{vpk.y}'
    sig,t1=sign(m,pid_str,vpk_str,vsk)
    result= ver_sig.ver_sig(sig,m,pid_str,vpk,t1)
    print('result:',result)





