from hashlib import sha256
import time
from fastecdsa import curve
from fastecdsa.point import Point


def gener(s1,s2,vpk,j,w,k):
    # 定义全局变量
    global s_in, s_ij

    # 获取当前时间戳
    t1= time.perf_counter()

    # 哈希j次,得到的结果是整数
    s_ij=sha256_n_times(s1,j)

    # print('s_ij的长度:', len(bin(s_ij)) - 2)      # 最大256位

    # 哈希n次,得到的结果是整数
    n=w-j+1
    s_in=sha256_n_times(s2,n)

    # 将vpk转为整数
    vpk_int=point_to_integer(vpk,curve.P256)
    # print('vpk：',vpk)
    # print('vpk_int：',vpk_int)

    # 两个大整数先异或，然后使用str()函数将它转换成一个字符串
    s=str(s_ij^s_in^k^vpk_int)

    # 生成假名
    pid=sha256(s.encode('utf-8')).digest()

    # 获取当前时间戳
    t2 = time.perf_counter()

    # 计算代码执行时间（单位：毫秒）
    elapsed_time = (t2 - t1) * 1000
    print("生成假名的时间: ", elapsed_time, "milliseconds")
    # print('s_ij:',s_ij)
    # print('s_in:',s_in)
    return pid


def sha256_n_times(num, n):
    """
    对大整数num进行n次sha256哈希
    """
    # 将大整数转换为字节数组
    global hash_result
    data = num.to_bytes((num.bit_length() + 7) // 8, byteorder='big')

    # 循环n次进行哈希
    for i in range(n):
        # 创建hash对象
        hash_obj = sha256()

        # 更新hash对象的输入数据
        hash_obj.update(data)

        # 获取哈希结果，并转换为字节数组
        hash_result = hash_obj.digest()

        # 将哈希结果作为下一次的输入数据
        data = hash_result

    # 将最终的哈希结果转换为整数
    hash_int = int.from_bytes(hash_result, byteorder='big')

    # 返回最终的哈希结果
    return hash_int
    # 将最终得到字符序列转为二进制字符串
    # return ''.join(format(byte, '08b') for byte in hash_result)


def point_to_integer(point: Point, curve: curve.Curve) -> int:
    x_bytes = point.x.to_bytes((curve.p.bit_length() + 7) // 8, 'big')
    y_bytes = point.y.to_bytes((curve.p.bit_length() + 7) // 8, 'big')
    combined_bytes = x_bytes + y_bytes
    return int.from_bytes(combined_bytes, 'big')