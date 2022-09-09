import aiohttp
import logging
import jwt
import time
import asyncio
from types import TracebackType
from typing import Optional, Type


class AioGCloud:
    logger_name = 'aio_gcloud'
    not_for_log = ['/id/auth/', '/iam/auth/']

    def __init__(self, url: str):
        self.logger = logging.getLogger(self.logger_name)
        self.base_url = url
        self.reseller_credentials = {}
        self.client_credentials = {}
        self.tries_count = 25
        self.page_items_limit = 200
        self.tcp_connector_limit = 50
        conn = aiohttp.TCPConnector(limit=self.tcp_connector_limit)
        self.session = aiohttp.ClientSession(base_url=url, connector=conn)
        self.logger.debug(f'Set base_url: "{url}"')

    ##########
    # Common #
    ##########
    async def _do_request(self, url: str, method: str, raise_for_status: bool = True, *args, **kwargs):
        self.logger.debug(f'{method}: {url}')
        for i in range(1, self.tries_count+1):
            try:
                resp = await self.session.request(url=url, method=method, timeout=300000,  *args, **kwargs)
                if raise_for_status:
                    resp.raise_for_status()
            except Exception as exp:
                self.logger.warning(f'{i} attempt failed: {exp}')
                if i > 5:
                    self.logger.warning(f'More than 5 attempt failed sleep(2)')
                    await asyncio.sleep(3)
                else:
                    await asyncio.sleep(1)
                if i >= self.tries_count:
                    raise exp
            else:
                break
        return resp

    async def _call_api(self, client_id: int = None, pagination: bool = False, *args, **kwargs):
        headers = {'Authorization': f'Bearer {await self._get_access_token(client_id)}'}
        if pagination:
            results = []
            if 'params' in kwargs:
                params = kwargs.pop('params')
            else:
                params = {}
            for i in self._page_params_generator():
                self.logger.debug(f'page: {i}')
                resp = await self._do_request(headers=headers, params=params | i, *args, **kwargs)
                resp_json = await resp.json()
                results.extend(resp_json['results'])
                if len(results) >= resp_json['count']:
                    break
        else:
            resp = await self._do_request(headers=headers, *args, **kwargs)
            results = await resp.json()
        return results

    @staticmethod
    def _decode_jwt(token: str) -> dict:
        return jwt.decode(token, algorithms=["RS256"], options={"verify_signature": False})

    def _is_token_expired(self, token):
        decoded_token = self._decode_jwt(token)
        if int(time.time()) > decoded_token.get('exp'):
            return True
        return False

    def _page_params_generator(self):
        limit = self.page_items_limit
        offset = 0
        while True:
            yield {'limit': limit,
                   'offset': offset}
            offset += limit

    async def _get_access_token(self, client_id: str):
        if client_id:
            access_token = await self._get_client_access_token(client_id)
        else:
            access_token = await self._get_reseller_access_token()
        return access_token

    async def _get_reseller_access_token(self):
        if not (self.reseller_credentials.get('access') and not self._is_token_expired(self.reseller_credentials.get('access'))):
            if self.reseller_credentials.get('refresh') and not self._is_token_expired(self.reseller_credentials.get('refresh')):
                tokens = await self._refresh_token(self.reseller_credentials.get('refresh'))
                self.reseller_credentials = self.reseller_credentials | tokens
            elif self.reseller_credentials.get('username') and self.reseller_credentials.get('password'):
                await self.reseller_login(username=self.reseller_credentials.get('username'),
                                          password=self.reseller_credentials.get('password'))
            else:
                self.logger.error('No credentials found!')
        return self.reseller_credentials.get('access')

    async def _get_client_access_token(self, client_id):
        creds = self.client_credentials.setdefault(client_id, {})
        if not (creds.get('access') and not self._is_token_expired(creds.get('access'))):
            if creds.get('refresh') and not self._is_token_expired(creds.get('refresh')):
                tokens = await self._refresh_token(creds.get('refresh'))
                creds.update(tokens)
            elif self.reseller_credentials:
                tokens = await self.get_client_admin_token(client_id)
                creds.update(tokens)
            else:
                self.logger.error('No credentials found!')
        return creds.get('access')

    async def reseller_login(self, username: str, password: str,):
        self.reseller_credentials['username'] = username
        self.reseller_credentials['password'] = password
        tokens = await self._login(username=username,
                                   password=password)
        self.reseller_credentials = self.reseller_credentials | tokens


    #############
    # Resellers #
    #############
    async def _login(self, username: str, password: str):
        resource_path = '/iam/auth/jwt/login'
        method = 'POST'
        body = {"username": username,
                "password": password}
        self.logger.debug(f'auth with: {username}')
        resp = await self._do_request(url=resource_path, method=method, json=body)
        tokens = await resp.json()
        return tokens

    async def _refresh_token(self, token: str):
        resource_path = '/iam/auth/jwt/refresh'
        method = 'POST'
        body = {"refresh": token}
        self.logger.debug(f'refresh token: {token[:10]}...')
        resp = await self._do_request(url=resource_path, method=method, json=body)
        tokens = await resp.json()
        return tokens

    async def get_client_admin_token(self, client_id: int):
        resource_path = f'/id/auth/jwt/clients/{client_id}/admin_token'
        method = 'GET'
        resp = await self._call_api(url=resource_path, method=method)
        return resp

    async def get_client(self, client_id: str):
        resource_path = f'/iam/clients/{client_id}'
        method = 'GET'
        resp = await self._call_api(url=resource_path, method=method, raise_for_status=True)
        return resp

    async def get_cloud_clients(self, state: str = 'active'):
        resource_path = '/iam/clients'
        method = 'GET'
        params = {'cloud': state}
        resp = await self._call_api(url=resource_path, method=method, params=params, raise_for_status=True,
                                    pagination=True)
        return resp

    async def get_users(self, client_id: str = None):
        resource_path = '/iam/users'
        method = 'GET'
        resp = await self._call_api(url=resource_path, method=method, client_id=client_id, raise_for_status=True,
                                    pagination=True)
        return resp


    #########
    # Cloud #
    #########
    async def list_regions(self, client_id: int = None):
        resource_path = '/cloud/v1/regions'
        method = 'GET'
        resp = await self._call_api(url=resource_path, method=method, client_id=client_id, pagination=True)
        return resp

    async def list_projects(self, client_id: int):
        resource_path = '/cloud/v1/projects'
        method = 'GET'
        resp = await self._call_api(url=resource_path, method=method, client_id=client_id, pagination=True)
        return resp

    async def list_flavors(self, project_id: int, region_id: int, client_id: int, include_prices='true'):
        resource_path = f'/cloud/v1/flavors/{project_id}/{region_id}'
        method = 'GET'
        params = {'include_prices': include_prices}
        resp = await self._call_api(url=resource_path, method=method, client_id=client_id, params=params, pagination=True)
        return resp

    async def list_bmflavors(self, project_id: int, region_id: int, client_id: int, include_prices='true'):
        resource_path = f'/cloud/v1/bmflavors/{project_id}/{region_id}'
        method = 'GET'
        params = {'include_prices': include_prices}
        resp = await self._call_api(url=resource_path, method=method, client_id=client_id, params=params, pagination=True)
        return resp

    async def list_instances(self, project_id: int, region_id: int, client_id: int, params: dict = {}):
        resource_path = f'/cloud/v1/instances/{project_id}/{region_id}'
        method = 'GET'
        resp = await self._call_api(url=resource_path, method=method, client_id=client_id, params=params, pagination=True)
        return resp

    async def list_loadbalancers(self, project_id: int, region_id: int, client_id: int, params: dict = {}):
        resource_path = f'/cloud/v1/loadbalancers/{project_id}/{region_id}'
        method = 'GET'
        resp = await self._call_api(url=resource_path, method=method, client_id=client_id, params=params, pagination=True)
        return resp

    async def search_instance_in_all_clients(self, instance_id: str = None, name: str = None):
        params = {}
        if instance_id:
            params['id'] = instance_id
        if name:
            params['name'] = name
        resource_path = '/cloud/v1/instances/search'
        method = 'GET'
        resp = await self._call_api(url=resource_path, method=method, params=params, pagination=True)
        return resp

    async def __aenter__(self) -> 'AioGCloud':
        return self

    async def __aexit__(
            self,
            exc_type: Optional[Type[BaseException]],
            exc_val: Optional[BaseException],
            exc_tb: Optional[TracebackType],
    ) -> None:
        await self.close()

    async def close(self) -> None:
        if self.session:
            await self.session.close()
