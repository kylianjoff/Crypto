import paho.mqtt.client as mqtt
import time

IP = "172.16.32.7"
PORT = 10801
GROUPE = "GROUPE_10"
SECRET = "........"

LOG_MQTT = False # Paramètre pour activer ou désactiver l'authentification MQTT
MQTT_LOGIN = "ANTIMUON"
MQTT_PASSWORD = "BY876F7F"

def on_connect(client, userdata, flags, rc, properties):
    print("--Connected with result code => "+mqtt.connack_string(rc))
    client.connected=(rc==0)

def on_subscribe(client, userdata, mid, granted_qos):
    print("--Subscribed: mid: " + str(mid) + " QoS" + str(granted_qos))

def on_message(client, userdata, msg):
    print("--Received message '" + str(msg.payload) + "' on topic '" + msg.topic + "' with QoS " + str(msg.qos))
    if "LED2_HACKED" in msg.topic and GROUPE in msg.topic:
        client.hacked=True
        print("\nWell done !")

    #Evite de travailler sur ces propres messages
    if not ("GROUPE_XX" in msg.topic):
        return

    #Construction du nouveau payload ICI

    if False:#si construction payload OK :
        topic=msg.topic
        topic=topic.replace("GROUPE_XX",GROUPE)
        topic=topic.replace("LED1","LED2")
        client.publish(topic,newpayload)

def on_publish(client, userdata, mid):
    print("--on_publish callback --mid: " + str(mid) )

client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="GROUPE")
client.connected=False
client.hacked=False
client.on_connect = on_connect
client.on_subscribe = on_subscribe
client.on_message = on_message
client.on_publish = on_publish

try:
    if(LOG_MQTT):
        client.username_pw_set(username=MQTT_LOGIN, password=MQTT_PASSWORD)
    client.connect(IP, PORT)
    client.subscribe("#", qos=0)
    client.loop_start()

    while not client.hacked:
        time.sleep(0.5)
        print(".",end='')


except ConnectionRefusedError:
    print("Connection Failed Bad IP / PORT")

except KeyboardInterrupt:
    print("\nBreak signal")
    pass

client.loop_stop()
client.unsubscribe("#")
client.disconnect()
print("Finished.")