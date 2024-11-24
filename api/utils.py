from influxdb_client import InfluxDBClient, QueryApi
from django.conf import settings
from collections import defaultdict


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


def process_sensor_data(tables):
    """
    Processes InfluxDB query results into a structured dictionary.

    Args:
        tables (list): List of InfluxDB tables with records.

    Returns:
        dict: Processed sensor data grouped by farmland ID and time.
    """
    sensor_data = defaultdict(list)

    for table in tables:
        for record in table.records:
            farmland_id = record.values.get("id")
            time = record.get_time()

            # Check if there's already an entry for this farmland and time
            existing_entry = next(
                (item for item in sensor_data[farmland_id] if item["time"] == time),
                None,
            )
            if existing_entry:
                # Add this field to the existing entry
                existing_entry[record.get_field()] = record.get_value()
            else:
                # Create a new entry
                sensor_data[farmland_id].append(
                    {
                        "time": time,
                        "location": record.values.get("location"),
                        record.get_field(): record.get_value(),
                    }
                )

    # Convert to a normal dict for JSON serialization
    return dict(sensor_data)
