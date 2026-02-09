"""MQTT service module using paho-mqtt."""

import socket
from typing import Optional

import paho.mqtt.client as mqtt

from core.models import Credential, Target
from modules.base import ServiceModule


class MQTTModule(ServiceModule):
    name = "mqtt"
    default_port = 1883
    alternate_ports = [8883]

    def test_credential(self, target: Target, credential: Credential, timeout: int = 5, **kwargs) -> bool:
        port = target.port or self.default_port
        result = {"connected": False, "done": False, "error": None}

        def on_connect(client, userdata, flags, rc, properties=None):
            # rc 0 = success, 4 = bad username/pass, 5 = not authorized
            if rc == 0:
                result["connected"] = True
            result["done"] = True
            client.disconnect()

        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
        client.username_pw_set(credential.username, credential.password)
        client.on_connect = on_connect

        if port == 8883:
            client.tls_set()
            client.tls_insecure_set(True)

        try:
            client.connect(target.host, port, keepalive=timeout)
            client.loop_start()

            # Wait for the callback
            import time
            waited = 0
            while not result["done"] and waited < timeout:
                time.sleep(0.1)
                waited += 0.1

            client.loop_stop()

            if not result["done"]:
                raise TimeoutError(f"MQTT connection to {target.host}:{port} timed out")

            return result["connected"]
        except socket.timeout:
            raise TimeoutError(f"MQTT connection to {target.host}:{port} timed out")
        except (ConnectionRefusedError, OSError) as e:
            raise

    def verify_access(self, target: Target, credential: Credential, timeout: int = 5, **kwargs) -> Optional[str]:
        port = target.port or self.default_port
        result = {"msg": None, "done": False}

        def on_connect(client, userdata, flags, rc, properties=None):
            if rc == 0:
                # Subscribe to $SYS topic for broker info
                client.subscribe("$SYS/broker/version", qos=0)
                client.subscribe("$SYS/broker/clients/connected", qos=0)
            else:
                result["done"] = True

        def on_message(client, userdata, msg):
            payload = msg.payload.decode("utf-8", errors="ignore")
            result["msg"] = f"{msg.topic}={payload}"
            result["done"] = True
            client.disconnect()

        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
        client.username_pw_set(credential.username, credential.password)
        client.on_connect = on_connect
        client.on_message = on_message

        if port == 8883:
            client.tls_set()
            client.tls_insecure_set(True)

        try:
            import time
            client.connect(target.host, port, keepalive=timeout)
            client.loop_start()
            waited = 0
            while not result["done"] and waited < timeout:
                time.sleep(0.1)
                waited += 0.1
            client.loop_stop()
            return result["msg"] or "Connected (no $SYS info)"
        except Exception:
            return None
