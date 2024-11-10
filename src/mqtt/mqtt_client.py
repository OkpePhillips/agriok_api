from paho.mqtt import client as mqtt
from src.certificates import ClientCert


# --- MQTTClient Class (Handles MQTT operations) ---
class MQTTClient:
    """
    Handles MQTT client operations, including secure connection, subscribing, and publishing messages.

    Attributes:
        client (mqtt.Client): The Paho MQTT client instance.
        broker (str): MQTT broker address.
        port (int): Port to connect to the MQTT broker.
    """

    def __init__(
        self,
        cert: ClientCert,
        client_id: str,
        broker: str,
        port: 8883,  
    ):
        """
        Initializes an MQTT client with SSL/TLS configuration for secure communication.

        Parameters:
            cert (ClientCert): Certificate paths for client and CA authentication.
            broker (str): The MQTT broker address.
            port (int): Port to connect to on the broker.
            client_id (str): Unique identifier for this MQTT client instance.
        """
        self.client = mqtt.Client(client_id=client_id)
        self.client.tls_set(cert.CERT_PATH, cert.KEY_PATH, cert.CA_CERT_PATH)
        self.broker = broker
        self.port = port

    def connect(self) -> None:
        """
        Establishes a secure connection to the MQTT broker using the configured SSL/TLS settings.
        """
        try:
            self.client.connect(self.broker, self.port)
            print("MQTT Client connected successfully.")
        except Exception as e:
            print(f"Failed to connect to MQTT broker: {e}")

    def subscribe(self, topic: str, on_message_callback) -> None:
        """
        Subscribes to a specified MQTT topic and assigns a callback function to handle incoming messages.

        Parameters:
            topic (str): The topic to subscribe to on the broker.
            on_message_callback (Callable): Function to handle messages received on this topic.
        """
        self.client.subscribe(topic)
        self.client.on_message = on_message_callback
        print(f"Subscribed to topic: {topic}")

    def publish(self, topic: str, payload: str) -> None:
        """
        Publishes a message to a specified MQTT topic.

        Parameters:
            topic (str): The topic on the broker to publish the message to.
            payload (str): The message payload to be sent.
        """
        self.client.publish(topic, payload)
        print(f"Published message to {topic}: {payload}")

    def loop_forever(self) -> None:
        """
        Starts a blocking loop to keep the client connected and process incoming messages indefinitely.
        """
        self.client.loop_forever()
