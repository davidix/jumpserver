# -*- coding: utf-8 -*-
#
from common.utils import get_logger
from secret.backends.pam.api.base import BasePam
from .dev import DevAPi
from .account import AccountAPi

__all__ = ['PamAPi', ]

logger = get_logger(__name__)


class PamAPi(DevAPi, AccountAPi, BasePam):

    def __init__(self, url, username=None, password=None):
        super().__init__(url, username, password)

    def package_dev_name(self, type_name, org_name, name='default'):
        type_name = self.DEV_TYPE_MAP[type_name]['name']
        return f'{name}({org_name}: {type_name})'

    @staticmethod
    def package_account_name(username, name):
        return f'{username}({name})'
