from django.apps import AppConfig
from influxdb_client import InfluxDBClient, Point
import json
from django.conf import settings
import asyncio
from src.certificates import ClientCert
from src.mqtt import MQTTClient
import threading
import atexit


class ApiConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "api"
    mqtt_thread_started = threading.Event()

    def ready(self):
        import api.signals

        asyncio.run(
            self.start_mqtt_service()
        )  # Use asyncio.run to manage the event loop

    async def start_mqtt_service(self):
        # Initialize MQTT client with certificates
        client_cert = ClientCert(
            "C:/Users/Rabony Globals/Documents/gig_at_startup/backend_certs/backend_cert.pem",
            "C:/Users/Rabony Globals/Documents/gig_at_startup/backend_certs/backend.key",
            "C:/Users/Rabony Globals/Documents/gig_at_startup/backend_certs/root_ca_cert.pem",
        )

        # Initialize MQTT Client
        mqtt_client = MQTTClient(client_cert, "test", "localhost", 8883)

        # Register the callback to handle incoming messages
        mqtt_client.on_message = self.save_data_to_db

        # Try to connect to the MQTT Broker
        try:
            mqtt_client.connect()
            print("Connected to MQTT Broker!")
        except Exception as e:
            print(f"Failed to connect: {e}")

        # Subscribe to the topic
        mqtt_client.subscribe("test/topic", self.save_data_to_db)

        # Start the MQTT client loop
        await asyncio.to_thread(mqtt_client.loop_forever)

    def save_data_to_db(self, client, userdata, message):
        """
        Callback function to save incoming MQTT message data to InfluxDB.
        """
        print("Message received!")
        print(message.payload)

        # Decode and parse the message payload as JSON
        try:
            data = json.loads(message.payload.decode("utf-8"))
        except json.JSONDecodeError as e:
            print(f"Error decoding JSON: {e}")
            return  # Exit the function if JSON decoding fails

        # Set up the InfluxDB client and API
        influx_client = InfluxDBClient(
            url=settings.INFLUXDB["url"],
            token=settings.INFLUXDB["token"],
            org=settings.INFLUXDB["org"],
        )

        try:
            # Create a point and write data to InfluxDB
            write_api = influx_client.write_api()
            point = (
                Point("temperature")  # Corrected typo
                .tag("location", "test")
                .field("value", data["value"])
            )
            write_api.write(
                bucket=settings.INFLUXDB["bucket"],
                org=settings.INFLUXDB["org"],
                record=point,
            )
        except Exception as e:
            print(f"Error writing to InfluxDB: {e}, Data: {data}")
        finally:
            influx_client.close()

    def shutdown(self):
        # Disconnect the MQTT client
        if hasattr(self, "mqtt_client"):
            self.mqtt_client.disconnect()
            print("MQTT client disconnected")
