import paho.mqtt.client as mqtt
import ssl

# MQTT broker information
# Define the client credentials.
client_ID = "publisher_test_computer"

broker_address = "mqtt.niels-bjorn.dk"  # Replace with your broker's address
port = 8883  # MQTT TLS port (usually 8883)
username = "rpimqttclient"  # Replace with your MQTT username (if required)
password = "pD2l0bYEw"  # Replace with your MQTT password (if required)
topic = "your_topic"  # Replace with the topic you want to subscribe or publish to

# TLS/SSL settings
ca_cert = "path_to_ca_cert.pem"  # Path to the CA certificate file
client_cert = "path_to_client_cert.pem"  # Path to the client certificate file
client_key = "path_to_client_key.pem"  # Path to the client private key file

def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print("Connected to MQTT broker")
        client.subscribe(topic)
    else:
        print(f"Connection failed with code {rc}")

def on_message(client, userdata, msg):
    print(f"Received message on topic '{msg.topic}': {msg.payload.decode()}")

# Create MQTT client

client = mqtt.Client()

client.username_pw_set(username, password)  # Set username and password (if required)

# Set TLS/SSL options
client.tls_set(ca_certs="/Users/nielsbjorn/Documents/Universitetet/Candidate/Code_examples/mqtt_certs/mqtt.pem",
            certfile="/Users/nielsbjorn/Documents/Universitetet/Candidate/Code_examples/mqtt_certs/mqtt.crt",
            keyfile="/Users/nielsbjorn/Documents/Universitetet/Candidate/Code_examples/mqtt_certs/mqtt.key", cert_reqs=ssl.CERT_REQUIRED,
            tls_version=ssl.PROTOCOL_TLS, ciphers=None)

# Set callback functions
client.on_connect = on_connect
client.on_message = on_message

# Connect to the MQTT broker
client.connect(broker_address, port)

# Start the MQTT loop (this keeps the script running)
client.loop_forever()
