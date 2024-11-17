import json
from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS
from django.conf import settings


def save_data_to_db(self, client, userdata, message):
    """
    Callback function to save incoming MQTT message data to InfluxDB dynamically.
    """
    print("Received message:", message.payload.decode())

    # Decode and parse the message payload as JSON
    try:
        data = json.loads(message.payload.decode("utf-8"))
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON: {e}")
        return  # Exit the function if JSON decoding fails

    # Set up the InfluxDB client
    influx_client = InfluxDBClient(
        url=settings.INFLUXDB["url"],
        token=settings.INFLUXDB["token"],
        org=settings.INFLUXDB["org"],
    )

    try:
        # Create the point dynamically
        point = Point("sensor_data")  # General measurement name
        if "tags" in data and isinstance(data["tags"], dict):
            for key, value in data["tags"].items():
                point = point.tag(key, value)

        if "fields" in data and isinstance(data["fields"], dict):
            for key, value in data["fields"].items():
                point = point.field(key, value)
        else:
            print("No valid 'fields' found in the payload.")
            return

        # Write data to InfluxDB
        write_api = influx_client.write_api(write_options=SYNCHRONOUS)
        write_api.write(
            bucket=settings.INFLUXDB["bucket"],
            org=settings.INFLUXDB["org"],
            record=point,
        )
        print(f"Data written to InfluxDB: {data}")

    except Exception as e:
        print(f"Error writing to InfluxDB: {e}, Data: {data}")
    finally:
        influx_client.close()

def save_data_to_db(self, client, userdata, message):
    """
    Save MQTT message data to InfluxDB dynamically, creating new measurements if needed.
    """
    print("Received message:", message.payload.decode())

    # Decode and parse the message payload as JSON
    try:
        data = json.loads(message.payload.decode("utf-8"))
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON: {e}")
        return  # Exit if JSON decoding fails

    # Validate the presence of the measurement key
    measurement = data.get("measurement", "sensors_data")
    if not isinstance(measurement, str) or not measurement.strip():
        print("Invalid measurement name. Using 'sensors_data'.")
        measurement = "sensors_data"

    # Set up the InfluxDB client
    influx_client = InfluxDBClient(
        url=settings.INFLUXDB["url"],
        token=settings.INFLUXDB["token"],
        org=settings.INFLUXDB["org"],
    )

    try:
        # Create the point dynamically
        point = Point(measurement)  # Use dynamic measurement name
        if "tags" in data and isinstance(data["tags"], dict):
            for key, value in data["tags"].items():
                point = point.tag(key, value)

        if "fields" in data and isinstance(data["fields"], dict):
            for key, value in data["fields"].items():
                point = point.field(key, value)
        else:
            print("No valid 'fields' found in the payload.")
            return

        # Write data to InfluxDB
        write_api = influx_client.write_api(write_options=SYNCHRONOUS)
        write_api.write(
            bucket=settings.INFLUXDB["bucket"],
            org=settings.INFLUXDB["org"],
            record=point,
        )
        print(f"Data written to InfluxDB in measurement '{measurement}': {data}")

    except Exception as e:
        print(f"Error writing to InfluxDB: {e}, Data: {data}")
    finally:
        influx_client.close()