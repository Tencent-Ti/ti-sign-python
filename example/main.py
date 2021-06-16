# -*- coding: utf-8 -*-
import sys
sys.path.append("..")
from tisign.sign import *


def build_http_header_with_signature():
    # 以Ti平台 查询用户是否拥有Admin权限 接口为例, 以下是接口的基本信息:
    # action: DescribeIsAdmin
    # service: ti-auth
    # version: 2020-10-10
    # content-type: application/json
    # http请求方法: POST
    # 网关访问地址: 127.0.0.1

    # 访问网关的host
    host = "127.0.0.1"
    # 服务接口
    action = 'DescribeIsAdmin'
    # 接口版本
    version = '2020-10-10'
    # 接口所属服务
    service = 'ti-auth'
    # http请求的content-type, 当前网关只支持: application/json  multipart/form-data
    conten_type = 'application/json'
    # http请求方法，当前网关只支持: POST GET
    http_method = 'POST'
    # Ti平台生成的鉴权密钥信息(通过 管理中心-个人中心-密钥管理 获取)
    secret_id = 'test-secret-id'
    secret_key = 'test-secret-key'

    # 创建TiSign对象
    ts = TiSign(host, action, version, service, conten_type,
                http_method, secret_id, secret_key)
    # 生成通过网关访问后端服务，所需http的请求header dict 和 签名信息
    http_header_dict, authorization = ts.build_header_with_signature()
    # 打印签名信息
    print("============= 签名字符串 Authorization =============")
    print("authorization: " + authorization)
    # 打印http header信息
    print("============ 通过网关访问后端服务Http请求头 ============")
    for key, value in http_header_dict.items():
        print(key + ": " + value)


if __name__ == "__main__":
    build_http_header_with_signature()
