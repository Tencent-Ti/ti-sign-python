# -*- coding: utf-8 -*-

from datetime import datetime
import hashlib
import sys
import hmac
import time


class TiSign(object):
    _canonical_uri = '/'
    _canonical_querystring = ''
    _signed_headers = 'content-type;host;x-tc-timestamp'
    _request_payload = ''
    _algorithm = 'TC3-HMAC-SHA256'
    _secret_id = ''
    _secret_key = ''
    _header = {}

    def __init__(self, host, action, version, service, content_type, http_method, secret_id, secret_key):
        # 请求header的host字段
        self.host = host
        # 请求接口action
        self.xtc_action = action
        # 请求接口版本
        self.xtc_version = version
        # 请求接口所属服务
        self.xtc_service = service
        # http请求Header的Content-type值，当前网关只支持: application/json  multipart/form-data
        self.content_type = content_type
        # http请求方法，当前网关只支持: POST GET
        self.http_method = http_method
        # secret_id, secret_key，Ti平台生成的签名凭证，非常重要，请妥善保管
        self._secret_id = secret_id
        self._secret_key = secret_key

    def build_header_with_signature(self):
      # 请求unix时间搓，精确到秒
        self.xtc_timestamp = int(time.time())
        self._header = {
            "Host":           self.host,
            "X-TC-Action":    self.xtc_action,
            "X-TC-Version":   self.xtc_version,
            "X-TC-Service":   self.xtc_service,
            "X-TC-Timestamp": str(self.xtc_timestamp),
            "Content-Type":   self.content_type,
        }

        # 1. 构造canonical_request 字符串
        # 1.1 拼接关键header信息，包括content-type和根域名host
        canonical_headers = 'content-type:%s\nhost:%s\nx-tc-timestamp:%s\n' % (
            self.content_type, self.host, str(self.xtc_timestamp))
        # 1.2 对常量request_payload进行hash计算
        if sys.version_info[0] == 3 and isinstance(self._request_payload, type("")):
            self._request_payload = self._request_payload.encode("utf8")
        payload_hash = hashlib.sha256(self._request_payload).hexdigest()
        # 1.3 按照固定格式拼接所有请求信息
        canonical_request = '%s\n%s\n%s\n%s\n%s\n%s' % (self.http_method,
                                                        self._canonical_uri,
                                                        self._canonical_querystring,
                                                        canonical_headers,
                                                        self._signed_headers,
                                                        payload_hash)

        # 2. 构造用于计算签名的字符串
        # 2.1 构造请求时间，根据请求header的X-TC-Timestamp字段(unix时间搓，精确到秒)，计算UTC标准日期
        date = datetime.utcfromtimestamp(
            int(self.xtc_timestamp)).strftime('%Y-%m-%d')
        # 2.2 构造凭证范围，固定格式为：Date/service/tc3_request
        credential_scope = date + '/' + self.xtc_service + '/tc3_request'
        # 2.3 对第1步构造的 canonical_request 进行hash计算
        if sys.version_info[0] == 3:
            canonical_request = canonical_request.encode("utf8")
        hash_canonical_request = hashlib.sha256(canonical_request).hexdigest()
        # 2.4 按照固定格式构造用于签名的字符串
        string2sign = '%s\n%s\n%s\n%s' % (self._algorithm,
                                          self.xtc_timestamp,
                                          credential_scope,
                                          hash_canonical_request)

        # 3. 对第2步构造的字符串进行签名
        # 3.1 用平台分配secret_key对步骤2计算的标准UTC时间进行hash计算，生成secret_date
        secret_date = self._hmac_sha256(
            ('TC3' + self._secret_key).encode('utf-8'), date)
        # 3.2 用3.1生成的secret_date对请求服务名进行hash计算，生成secret_service
        secret_service = self._hmac_sha256(
            secret_date.digest(), self.xtc_service)
        # 3.3 用3.2生成的secret_service对tc3_request常量字符串进行hash计算, 生成新secret_key
        secret_key = self._hmac_sha256(secret_service.digest(), 'tc3_request')
        # 3.4 用3.3生成的secretKey对第2构造的签名字符串进行hash计算，并生成最终的签名字符串
        signature = self._hmac_sha256(
            secret_key.digest(), string2sign).hexdigest()

        # 4. 构造http请求头的authorization字段
        # 4.1 按照固定格式构造authorization字符串
        authorization = "TC3-HMAC-SHA256"
        authorization += " Credential=%s/%s" % (
            self._secret_id, credential_scope)
        authorization += ", SignedHeaders=content-type;host;x-tc-timestamp, Signature=%s" % signature
        self._header["Authorization"] = authorization
        return self._header, authorization

    def _hmac_sha256(self, key, msg):
        return hmac.new(key, msg.encode('utf-8'), hashlib.sha256)
