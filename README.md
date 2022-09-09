# aiogcore-cloud

## **Install:**
```bash
python3 -m pip install aiogcloud --upgrade -i https://artifactory.wgdp.io/api/pypi/wgsa-pypi/simple --extra-index-url https://pypi.python.org/simple
```

## **How to use:**
```python

username = 'i_ivanov'
password = '****'
url = 'https://api.gcorelabs.com/'


async with AioGCloud(url=url) as gcloud_client:
    await gcloud_client.reseller_login(username=username, password=password)
    
    #Get Cloud clients
    cloud_clients = await gc.get_cloud_clients()

    #Get Cloud Regions
    client_id = cloud_clients[0]['id']
    cloud_regions = await gc.list_regions(client_id)

    #Get All projects in all clients
    resp = await asyncio.gather(*[gcloud_client.list_projects(c['id']) for c in cloud_clients])
    cloud_projects = [i for r in resp for i in r]

    #Get All instances in all projects in all clients
    tasks = [gcloud_client.list_instances(p['id'], r['id'], p['client_id'], {'include_baremetal': 'true'}) for r in cloud_regions for p in cloud_projects]
    log.debug(f'Run list_instances. Request count {len(tasks)} ')
    result = await asyncio.gather(*tasks)
    cloud_instances = [i for r in result for i in r]

```
