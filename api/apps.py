from django.apps import AppConfig
from influxdb_client import InfluxDBClient, Point
import json
from django.conf import settings
import threading
from src.certificates import ClientCert
from src.mqtt import MQTTClient


class ApiConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "api"
    mqtt_client = None

    def ready(self):
        import api.signals

        # Start MQTT in a separate thread using asyncio properly
        threading.Thread(target=self.start_mqtt_service, daemon=True).start()

    def start_mqtt_service(self):
        """
        Starts the MQTT service in a new thread using an event loop.
        """
        # Running the asynchronous function in the event loop
        self.run_mqtt_client()

    def mqtt_wrapper(self):

        self.mqtt_client.connect()
        self.mqtt_client.subscribe("test/finally", self.save_data_to_db)
        self.mqtt_client.loop_forever()

    def run_mqtt_client(self):
        """
        This method is responsible for setting up and running the MQTT client.
        """
        if self.mqtt_client is None:
            client_cert = ClientCert(
                "C:/Users/Rabony Globals/Documents/gig_at_startup/backend_certs/backend_cert.pem",
                "C:/Users/Rabony Globals/Documents/gig_at_startup/backend_certs/backend.key",
                "C:/Users/Rabony Globals/Documents/gig_at_startup/backend_certs/root_ca_cert.pem",
            )

            # Initialize MQTT Client
            self.mqtt_client = MQTTClient(
                client_cert, "test", "ec2-18-206-126-63.compute-1.amazonaws.com", 8883
            )

            # Register the callback to handle incoming messages
            self.mqtt_client.on_message = self.save_data_to_db

            # Try to connect to the MQTT Broker
            try:
                self.mqtt_wrapper()
            except Exception as e:
                print(f"Failed to initiate thread: {e}")
                return

    def save_data_to_db(self, client, userdata, message):
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
            url=settings.INFLUXDB["url"],
            token=settings.INFLUXDB["token"],
            org=settings.INFLUXDB["org"],
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
                bucket=settings.INFLUXDB["bucket"],
                org=settings.INFLUXDB["org"],
                record=point,
            )
        except Exception as e:
            print(f"Error writing to InfluxDB: {e}, Data: {data}")
        finally:
            influx_client.close()


