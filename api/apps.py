from django.apps import AppConfig
from influxdb_client import InfluxDBClient, Point
import json
from django.conf import settings
import asyncio
from src.certificates import ClientCert
from src.mqtt import MQTTClient


class ApiConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "api"

    def ready(self):
        import api.signals

        asyncio.get_event_loop().create_task(self.start_mqtt_client())

    async def start_mqtt_client(self):
        """
        Starts the MQTT client in an asynchronous manner.
        """
        # Initialize your client certificate
        client_cert = ClientCert(
            "./backend_certs/backend_cert.pem",
            "./backend_certs/backend.key",
            "./backend_certs/root_ca_cert.pem",
        )

        # Initialize MQTT Client
        mqtt_client = MQTTClient(client_cert, "Test", "132.23.21.33")

        # Connect the client
        mqtt_client.connect()

        # Define your callback function to process messages
        def save_data_to_db(client, userdata, message):
            # Logic to save or process the received message
            try:
                # Decode and parse the message payload as JSON
                data = json.loads(message.payload.decode("utf-8"))
            except json.JSONDecodeError as e:
                print(f"Error decoding JSON: {e}")
                return  # Exit the function if JSON decoding fails

            # Set up the InfluxDB client and API
            client = InfluxDBClient(
                url=settings.INFLUXDB["url"],
                token=settings.INFLUXDB["token"],
                org=settings.INFLUXDB["org"],
            )

            try:
                # Create a point and write data to InfluxDB
                write_api = client.write_api()
                point = (
                    Point("temperatre")
                    .tag("location", "test")
                    .field("value", data["value"])
                )
                write_api.write(
                    bucket=settings.INFLUXDB["bucket"],
                    org=settings.INFLUXDB["org"],
                    record=point,
                )

            except Exception as e:
                print(f"Error writing to InfluxDB: {e}")

            finally:
                client.close()

        # Subscribe to a topic and attach the callback function
        mqtt_client.subscribe("test/data", save_data_to_db)

        # Start the loop in the background
        await asyncio.to_thread(mqtt_client.loop_forever)
