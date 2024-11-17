from influxdb_client import InfluxDBClient, QueryApi
from django.conf import settings


def query_influxdb(query):
    """
    Execute a query against InfluxDB and return results.
    """
    client = InfluxDBClient(
        url=settings.INFLUXDB["url"],
        token=settings.INFLUXDB["token"],
        org=settings.INFLUXDB["org"],
    )
    try:
        query_api = client.query_api()
        results = query_api.query(query=query, org=settings.INFLUXDB["org"])
        return results
    except Exception as e:
        print(f"Error querying InfluxDB: {e}")
        return None
    finally:
        client.close()
