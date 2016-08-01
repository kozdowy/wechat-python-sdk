# -*- coding: utf-8 -*-

import json
import requests
import grequests
import six
import copy

from wechat_sdk.exceptions import OfficialAPIError


class WechatRequest(object):
    """ WechatRequest 请求类

    对微信服务器的请求响应处理进行封装
    """

    def __init__(self, conf=None):
        """
        :param conf: WechatConf 配置类实例
        """
        self.__conf = conf
        self.__session = requests.Session()

    def request(self, method, url, access_token=None, **kwargs):
        """
        向微信服务器发送请求
        :param method: 请求方法
        :param url: 请求地址
        :param access_token: access token 值, 如果初始化时传入 conf 会自动获取, 如果没有传入则请提供此值
        :param kwargs: 附加数据
        :return: 微信服务器响应的 JSON 数据
        """
        access_token = self.__conf.access_token if self.__conf is not None else access_token
        if "params" not in kwargs:
            kwargs["params"] = {
                "access_token": access_token
            }
        else:
            kwargs["params"]["access_token"] = access_token

        if isinstance(kwargs.get("data", ""), dict):
            body = json.dumps(kwargs["data"], ensure_ascii=False)
            if isinstance(body, six.text_type):
                body = body.encode('utf8')
            kwargs["data"] = body

        r = grequests.request(
            method=method,
            url=url,
            session=self.__session,
            **kwargs
        )
        r.send()
        res = r.response
        res.raise_for_status()
        try:
            response_json = res.json()
        except ValueError:  # 非 JSON 数据
            return res

        headimgurl = response_json.get('headimgurl')
        if headimgurl:
            response_json['headimgurl'] = headimgurl.replace('\\', '')
        self._check_official_error(response_json)
        return response_json

    def mass_request(self, method, url, access_token=None, **kwargs):
        """
        Handles large numbers of requests going to the same url
        The data/params keywords should be replaced with data_list and param_list
        with each item being a full set of data or params that would be sent
        for a regular request
        :param method: 请求方法
        :param url: 请求地址
        :param access_token: access token 值, 如果初始化时传入 conf 会自动获取, 如果没有传入则请提供此值
        :param kwargs: 附加数据
        :return: [JSON]
        """
        access_token = self.__conf.access_token if self.__conf is not None else access_token
        if "params" not in kwargs:
            kwargs["params"] = {
                "access_token": access_token
            }
        else:
            kwargs["params"]["access_token"] = access_token

        split_kwargs = []
        if isinstance(kwargs.get("data_list", ""), list):
            new_kw = {}
            for data in kwargs.get("data_list"):
                new_kw = copy.deepcopy(kwargs)
                body = data
                if isinstance(data, dict):
                    body = json.dumps(data, ensure_ascii=False)
                    if isinstance(body, six.text_type):
                        body = body.encode('utf8')
                new_kw["data"] = body
                del new_kw["data_list"]
                split_kwargs.append(new_kw)
        elif isinstance(kwargs.get("param_list", ""), list):
            for param in kwargs.get("param_list"):
                new_kw = copy.deepcopy(args)
                param["access_token"] = access_token
                new_kw["params"] = param
                split_kwargs.append(new_kw)

        rs = (grequests.request(method=method,
                                url=url,
                                session=self.__session,
                                **kw)
              for kw in split_kwargs
        )

        responses = grequests.map(rs, size=50)
        return_json = []
        for res in responses:
            res.raise_for_status()
            try:
                response_json = res.json()
            except ValueError:  # 非 JSON 数据
                return_json.append(res)
                continue

            headimgurl = response_json.get('headimgurl')
            if headimgurl:
                response_json['headimgurl'] = headimgurl.replace('\\', '')
            self._check_official_error(response_json)
            return_json.append(response_json)
        return return_json

    def get(self, url, access_token=None, **kwargs):
        """
        使用 GET 方法向微信服务器发出请求
        :param url: 请求地址
        :param access_token: access token 值, 如果初始化时传入 conf 会自动获取, 如果没有传入则请提供此值
        :param kwargs: 附加数据
        :return: 微信服务器响应的 JSON 数据
        """
        return self.request(
            method="get",
            url=url,
            access_token=access_token,
            **kwargs
        )

    def post(self, url, access_token=None, **kwargs):
        """
        使用 POST 方法向微信服务器发出请求
        :param url: 请求地址
        :param access_token: access token 值, 如果初始化时传入 conf 会自动获取, 如果没有传入则请提供此值
        :param kwargs: 附加数据
        :return: 微信服务器响应的 JSON 数据
        """
        return self.request(
            method="post",
            url=url,
            access_token=access_token,
            **kwargs
        )

    def _check_official_error(self, json_data):
        """
        检测微信公众平台返回值中是否包含错误的返回码
        :raises OfficialAPIError: 如果返回码提示有错误，抛出异常；否则返回 True
        """
        if 'errcode' in json_data and json_data['errcode'] != 0:
            raise OfficialAPIError(errcode=json_data.get('errcode'), errmsg=json_data.get('errmsg', ''))
