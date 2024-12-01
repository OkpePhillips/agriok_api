from influxdb_client import InfluxDBClient, Point
import json
from django.conf import settings
from src.certificates import ClientCert
from src.mqtt import MQTTClient
import os
from dotenv import load_dotenv


load_dotenv()

def run_mqtt_client():
    """
    This method is responsible for setting up and running the MQTT client.
    """
    client_cert = ClientCert(
        "C:/Users/Rabony Globals/Documents/gig_at_startup/backend_certs/backend_cert.pem",
        "C:/Users/Rabony Globals/Documents/gig_at_startup/backend_certs/backend.key",
        "C:/Users/Rabony Globals/Documents/gig_at_startup/backend_certs/root_ca_cert.pem",
    )

        # Initialize MQTT Client
    mqtt_client = MQTTClient(
        client_cert, "test", "ec2-34-239-132-136.compute-1.amazonaws.com", 8883
    )

    # Register the callback to handle incoming messages
    mqtt_client.on_message = save_data_to_db

    # Try to connect to the MQTT Broker
    mqtt_client.connect()
    mqtt_client.subscribe("test/finally", save_data_to_db)
    mqtt_client.loop_forever()

def save_data_to_db(client, userdata, message):
    """
    Callback function to save incoming MQTT message data to InfluxDB.
    """
    print(message.payload.decode())
    # Decode and parse the message payload as JSON
    try:
        data = json.loads(message.payload.decode("utf-8"))
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON: {e}")
        return  # Exit the function if JSON decoding fails

    if "data" not in data:
        print(f"Missing 'data' key in JSON payload: {data}")
        return

    try:
        sensor_data = data["data"]
    except KeyError as e:
        print(f"Missing key in JSON payload: {e}")
        return

    farm_id = data.get("id", None)

    # Set up the InfluxDB client and API
    influx_client = InfluxDBClient(
        url=os.getenv("INFLUX_DB_URL"),
        token=os.getenv("INFLUX_DB_TOKEN"),
        org=os.getenv("INFLUX_DB_ORG"),
    )

    try:
        # Create a point and write data to InfluxDB
        write_api = influx_client.write_api()
        point = Point("SensorData").tag("location", "test")

        if farm_id is not None:
            point = point.tag("id", str(farm_id))

        for key, value in sensor_data.items():
            point = point.field(key, value)

        write_api.write(
            bucket=os.getenv("INFLUX_DB_BUCKET"),
            org=os.getenv("INFLUX_DB_ORG"),
            record=point,
        )
    except Exception as e:
        print(f"Error writing to InfluxDB: {e}, Data: {data}")
    finally:
        influx_client.close()


if __name__ == '__main__':
    run_mqtt_client()

