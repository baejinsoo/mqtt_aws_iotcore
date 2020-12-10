# mqtt_aws_iotcore

- AWS Iot core에 MQTT 메시지 게시 방법 (퍼블리셔 생성)
- Subscirbe 구현

## 1. AWS Iot core에 MQTT 메시지 게시 방법 (퍼블리셔 생성)

**MQTT 게시를 테스트할 디렉터리 설정**

\1.  개발 환경에서 작업 디렉터리(예: **iot-test-publish**)를 생성합니다.

\2.  새 작업 디렉터리에서 인증서를 넣을 하위 디렉터리(예: **certificates**)를 생성합니다.

\3.  명령줄에서 디렉터리를 새 작업 디렉터리로 변경합니다.

**Python용 AWS IoT SDK 및 pip 설치**

\1.  Python 3 패키징용 pip를 아직 설치하지 않았다면 설치합니다. 자세한 내용은 Python Packaging Authority(PyPA) 웹 사이트의 [Installation](https://pip.pypa.io/en/stable/installing/)을 참조하십시오.

\2.  명령줄에서 다음을 실행하여 Python v2용 AWS IoT SDK를 설치합니다.

```plainText
pip install awsiotsdk
```

-또는-

원하는 경우 다음 명령을 실행하여 Python용 AWS IoT 디바이스 SDK(이전 SDK 버전)를 설치합니다.

```plainText
pip install AWSIoTPythonSDK
```

자세한 내용은 GitHub에서 [AWS IoT SDK for Python v2](https://github.com/aws/aws-iot-device-sdk-python-v2#aws-iot-sdk-for-python-v2) 또는 [AWS IoT Device SDK for Python](https://github.com/aws/aws-iot-device-sdk-python)을 참조하십시오.

**참고:** 이러한 SDK는 AWS IoT Core에 연결하는 것이 좋지만, 필수 사항은 아닙니다. 또한 호환되는 타사 MQTT 클라이언트를 사용하여 연결할 수도 있습니다.

**AWS IoT Core 정책 생성**

\1.  [AWS IoT Core 콘솔](https://console.aws.amazon.com/iot/)을 엽니다.

\2.  왼쪽 탐색 창에서 [**보안**]을 선택합니다.

\3.  [**보안**]에서 [**정책**]을 선택합니다.

\4.  기존 AWS IoT Core 정책이 있는 경우 [**생성**]을 선택하여 새 정책을 생성합니다.
-또는-
[**아직 정책이 없습니다.**] 페이지에서 [**정책 생성**]을 선택합니다.

\5.  [**정책 생성**] 페이지에서 정책의 [**이름**]을 입력합니다. 예를 들어, **admin**과 같습니다.

\6.  [**설명문 추가**]에서 다음을 수행합니다.
[**작업**]에 **iot:\***를 입력합니다.
**참고:** 모든 AWS IoT 작업을 허용하면(**iot:\***) 테스트에 유용합니다. 하지만 프로덕션 설정의 보안을 강화하는 것이 모범 사례입니다. 보다 안전한 정책 예제는 [AWS IoT 정책 예제](https://docs.aws.amazon.com/iot/latest/developerguide/example-iot-policies.html)를 참조하십시오.
[**리소스 ARN**]에 *****를 입력합니다.
[**효과**]에서 [**허용**] 확인란을 선택합니다.

\7.  [**생성**]을 선택합니다.

자세한 내용은 [AWS IoT Core 정책 생성](https://docs.aws.amazon.com/iot/latest/developerguide/create-iot-policy.html) 및 [AWS IoT Core 정책](https://docs.aws.amazon.com/iot/latest/developerguide/iot-policies.html)을 참조하십시오.

**AWS IoT 사물 생성**

**참고:** AWS IoT에 연결할 사물을 생성할 필요는 없습니다. 하지만 사물을 활용하면 [추가 보안 제어](https://docs.aws.amazon.com/iot/latest/developerguide/thing-groups.html#group-attach-policy)뿐만 아니라 [플릿 인덱싱](https://docs.aws.amazon.com/iot/latest/developerguide/iot-indexing.html), [작업](https://docs.aws.amazon.com/iot/latest/developerguide/iot-jobs.html), 또는 [디바이스 섀도우](https://docs.aws.amazon.com/iot/latest/developerguide/iot-device-shadows.html)와 같은 다른 AWS IoT 기능을 사용할 수 있습니다.

\1.  [AWS IoT Core 콘솔](https://console.aws.amazon.com/iot/)의 왼쪽 탐색 창에서 [**관리**]를 선택합니다.

\2.  기존 사물이 있는 경우 [**생성**]을 선택하여 새 사물을 생성합니다.
-또는-
[**아직 사물이 없습니다.**] 페이지에서 [**사물 등록**]을 선택합니다.

\3.  [**AWS IoT 사물 생성**] 페이지에서 [**단일 사물 생성**]을 선택합니다.

\4.  [**사물 레지스트리에 디바이스 추가**] 페이지에서 다음을 수행합니다.
사물의 [**이름**]을 입력합니다. 예를 들어, **Test-Thing**과 같습니다.
(선택 사항) [**이 사물에 유형 추가**]에서 [[사물 유형](https://docs.aws.amazon.com/iot/latest/developerguide/thing-types.html)]을 선택하거나 생성합니다.
(선택 사항) [**그룹에 이 사물 추가**]에서 그룹을 선택하거나 생성합니다. 그룹에 대한 자세한 내용은 [정적 사물 그룹](https://docs.aws.amazon.com/iot/latest/developerguide/thing-groups.html) 및 [동적 사물 그룹](https://docs.aws.amazon.com/iot/latest/developerguide/dynamic-thing-groups.html)을 참조하십시오.
(선택 사항) [**검색 가능한 사물 속성 설정 (선택 사항)**]에서 속성을 키–값 페어로 추가합니다.
[**다음**]을 선택합니다.

\5.  [**사물에 인증서 추가**] 페이지에서 [**인증서 생성**]을 선택합니다. 사물 및 사물에 대한 인증서가 생성되었음을 확인하는 알림이 표시됩니다.

\6.  [**인증서 생성 완료**] 페이지에서 다음을 수행합니다.
[**디바이스에 연결하려면 다음을 다운로드해야 합니다.**]에서 인증서, 퍼블릭 키 및 프라이빗 키에 대한 [**다운로드**]를 선택합니다.
다운로드한 각 파일을 앞서 생성한 certificates 하위 디렉터리에 저장합니다.
[**AWS IoT의 루트 CA도 다운로드해야 합니다.**]에서 [**다운로드**]를 선택합니다. [**서버 인증**] 페이지의 [[서버 인증을 위한 CA 인증서](https://docs.aws.amazon.com/iot/latest/developerguide/server-authentication.html#server-authentication-certs)]가 열립니다.

\7.  [**Amazon Trust Services 엔드포인트(기본 설정)**]에서 [[Amazon Root CA 1](https://www.amazontrust.com/repository/AmazonRootCA1.pem)]을 선택합니다. 브라우저에서 인증서가 열립니다.

\8.  인증서(**-----BEGIN CERTIFICATE-----**에서 **-----END CERTIFICATE-----**까지 모든 내용)를 복사하여 텍스트 편집기에 붙여넣습니다.

\9.  인증서를 certificates 하위 디렉터리에 **root.pem**이라는 .pem 파일로 저장합니다.

\10.  AWS IoT Core 콘솔의 [**인증서 생성 완료**] 페이지에서 [**활성화**]를 선택합니다. 그러면 버튼이 [**비활성화**]로 변경됩니다.

\11.  [**정책 연결**]을 선택합니다.

\12.  [**사물에 정책 추가**] 페이지에서 다음을 수행합니다.
이전에 생성한 AWS IoT Core 정책을 선택합니다. 예를 들어, **admin**과 같습니다.
[**사물 등록**]을 선택합니다.

자세한 내용은 다음 페이지를 참조하십시오.

- [사물 생성](https://docs.aws.amazon.com/iot/latest/developerguide/create-aws-thing.html)
- [디바이스 인증서 생성 및 활성화](https://docs.aws.amazon.com/iot/latest/developerguide/create-device-certificate.html)
- [디바이스 인증서에 AWS IoT Core 정책 연결](https://docs.aws.amazon.com/iot/latest/developerguide/attach-policy-to-certificate.html)

**AWS IoT Core 엔드포인트 URL 복사**

\1.  [AWS IoT Core 콘솔](https://console.aws.amazon.com/iot/)의 왼쪽 탐색 창에서 [**설정**]을 선택합니다.

\2.  [**설정**] 페이지의 [**사용자 지정 엔드포인트**]에서 [**엔드포인트**]를 복사합니다. 이 AWS IoT Core 사용자 지정 엔드포인트 URL은 AWS 계정 및 리전에 대해 개인적으로 지정됩니다.

**Python 프로그램 파일 생성**

다음 Python 코드 예제 중 하나를 **publish.py**라는 Python 프로그램 파일로 저장합니다. 앞서 Python v2용 AWS IoT SDK를 설치한 경우 이 예제 코드를 사용합니다.

**참고:** **customEndpointUrl**을 AWS IoT Core 사용자 지정 엔드포인트 URL로 바꿉니다. **certificates**를 certificates 하위 디렉터리 이름으로 바꿉니다. **a1b23cd45e-certificate.pem.crt**를 클라이언트 .crt 이름으로 바꿉니다. **a1b23cd45e-private.pem.key**를 프라이빗 키 이름으로 바꿉니다.

```plainText
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

from awscrt import io, mqtt, auth, http
from awsiot import mqtt_connection_builder
import time as t
import json

# Define ENDPOINT, CLIENT_ID, PATH_TO_CERT, PATH_TO_KEY, PATH_TO_ROOT, MESSAGE, TOPIC, and RANGE
ENDPOINT = "customEndpointUrl"
CLIENT_ID = "testDevice"
PATH_TO_CERT = "certificates/a1b23cd45e-certificate.pem.crt"
PATH_TO_KEY = "certificates/a1b23cd45e-private.pem.key"
PATH_TO_ROOT = "certificates/root.pem"
MESSAGE = "Hello World"
TOPIC = "test/testing"
RANGE = 20

# Spin up resources
event_loop_group = io.EventLoopGroup(1)
host_resolver = io.DefaultHostResolver(event_loop_group)
client_bootstrap = io.ClientBootstrap(event_loop_group, host_resolver)
mqtt_connection = mqtt_connection_builder.mtls_from_path(
            endpoint=ENDPOINT,
            cert_filepath=PATH_TO_CERT,
            pri_key_filepath=PATH_TO_KEY,
            client_bootstrap=client_bootstrap,
            ca_filepath=PATH_TO_ROOT,
            client_id=CLIENT_ID,
            clean_session=False,
            keep_alive_secs=6
            )
print("Connecting to {} with client ID '{}'...".format(
        ENDPOINT, CLIENT_ID))
# Make the connect() call
connect_future = mqtt_connection.connect()
# Future.result() waits until a result is available
connect_future.result()
print("Connected!")
# Publish message to server desired number of times.
print('Begin Publish')
for i in range (RANGE):
    data = "{} [{}]".format(MESSAGE, i+1)
    message = {"message" : data}
    mqtt_connection.publish(topic=TOPIC, payload=json.dumps(message), qos=mqtt.QoS.AT_LEAST_ONCE)
    print("Published: '" + json.dumps(message) + "' to the topic: " + "'test/testing'")
    t.sleep(0.1)
print('Publish End')
disconnect_future = mqtt_connection.disconnect()
disconnect_future.result()
```

Python용 AWS IoT 디바이스 SDK(이전 SDK 버전)를 설치한 경우 이 예제 코드를 사용합니다.

**참고:** **customEndpointUrl**을 AWS IoT Core 사용자 지정 엔드포인트 URL로 바꿉니다. **certificates**를 certificates 하위 디렉터리 이름으로 바꿉니다. **a1b23cd45e-certificate.pem.crt**를 클라이언트 .crt 이름으로 바꿉니다. **a1b23cd45e-private.pem.key**를 프라이빗 키 이름으로 바꿉니다.

```plainText
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import time as t
import json
import AWSIoTPythonSDK.MQTTLib as AWSIoTPyMQTT

# Define ENDPOINT, CLIENT_ID, PATH_TO_CERT, PATH_TO_KEY, PATH_TO_ROOT, MESSAGE, TOPIC, and RANGE
ENDPOINT = "customEndpointUrl"
CLIENT_ID = "testDevice"
PATH_TO_CERT = "certificates/a1b23cd45e-certificate.pem.crt"
PATH_TO_KEY = "certificates/a1b23cd45e-private.pem.key"
PATH_TO_ROOT = "certificates/root.pem"
MESSAGE = "Hello World"
TOPIC = "test/testing"
RANGE = 20

myAWSIoTMQTTClient = AWSIoTPyMQTT.AWSIoTMQTTClient(CLIENT_ID)
myAWSIoTMQTTClient.configureEndpoint(ENDPOINT, 8883)
myAWSIoTMQTTClient.configureCredentials(PATH_TO_ROOT, PATH_TO_KEY, PATH_TO_CERT)

myAWSIoTMQTTClient.connect()
print('Begin Publish')
for i in range (RANGE):
    data = "{} [{}]".format(MESSAGE, i+1)
    message = {"message" : data}
    myAWSIoTMQTTClient.publish(TOPIC, json.dumps(message), 1) 
    print("Published: '" + json.dumps(message) + "' to the topic: " + "'test/testing'")
    t.sleep(0.1)
print('Publish End')
myAWSIoTMQTTClient.disconnect()
```

**설정 테스트**

\1.  [AWS IoT Core 콘솔](https://console.aws.amazon.com/iot/)의 왼쪽 탐색 창에서 [**테스트**]를 선택합니다.

\2.  [**MQTT 클라이언트**] 페이지의 [**구독 주제**]에 **test/testing**을 입력합니다.

\3.  [**주제 구독**]을 선택합니다. **test/testing**이라는 테스트 주제를 테스트 메시지 게시에 사용할 준비가 되었습니다. 자세한 내용은 [AWS IoT MQTT 클라이언트를 사용하여 MQTT 메시지 보기](https://docs.aws.amazon.com/iot/latest/developerguide/view-mqtt-messages.html)를 참조하십시오.

\4.  명령줄에서 다음을 실행합니다.

```plainText
python3 publish.py
```

Python 프로그램은 AWS IoT Core 콘솔에서 생성한 주제 **test/testing** 주제에 20개의 테스트 메시지를 게시합니다. 콘솔에서 주제를 보고 게시된 메시지를 확인합니다.





# 2. Subscirbe 구현

```python
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0.
import argparse
from awscrt import io, mqtt, auth, http
from awsiot import mqtt_connection_builder
import sys
import threading
import time
from uuid import uuid4

# This sample uses the Message Broker for AWS IoT to send and receive messages
# through an MQTT connection. On startup, the device connects to the server,
# subscribes to a topic, and begins publishing messages to that topic.
# The device should receive those same messages back from the message broker,
# since it is subscribed to that same topic.

parser = argparse.ArgumentParser(description="Send and receive messages through and MQTT connection.")
parser.add_argument('--endpoint', required=True, help="Your AWS IoT custom endpoint, not including a port. " +
                                                      "Ex: \"abcd123456wxyz-ats.iot.us-east-1.amazonaws.com\"")
parser.add_argument('--cert', help="File path to your client certificate, in PEM format.")
parser.add_argument('--key', help="File path to your private key, in PEM format.")
parser.add_argument('--root-ca', help="File path to root certificate authority, in PEM format. " +
                                      "Necessary if MQTT server uses a certificate that's not already in " +
                                      "your trust store.")
parser.add_argument('--client-id', default="test-" + str(uuid4()), help="Client ID for MQTT connection.")
parser.add_argument('--topic', default="test/topic", help="Topic to subscribe to, and publish messages to.")
parser.add_argument('--message', default="Hello World!", help="Message to publish. " +
                                                              "Specify empty string to publish nothing.")
parser.add_argument('--count', default=15, type=int, help="Number of messages to publish/receive before exiting. " +
                                                          "Specify 0 to run forever.")
parser.add_argument('--use-websocket', default=False, action='store_true',
    help="To use a websocket instead of raw mqtt. If you " +
    "specify this option you must specify a region for signing, you can also enable proxy mode.")
parser.add_argument('--signing-region', default='us-east-1', help="If you specify --use-web-socket, this " +
    "is the region that will be used for computing the Sigv4 signature")
parser.add_argument('--proxy-host', help="Hostname for proxy to connect to. Note: if you use this feature, " +
    "you will likely need to set --root-ca to the ca for your proxy.")
parser.add_argument('--proxy-port', type=int, default=8080, help="Port for proxy to connect to.")
parser.add_argument('--verbosity', choices=[x.name for x in io.LogLevel], default=io.LogLevel.NoLogs.name,
    help='Logging level')

# Using globals to simplify sample code
args = parser.parse_args()

io.init_logging(getattr(io.LogLevel, args.verbosity), 'stderr')

received_count = 0
received_all_event = threading.Event()

# Callback when connection is accidentally lost.
def on_connection_interrupted(connection, error, **kwargs):
    print("Connection interrupted. error: {}".format(error))


# Callback when an interrupted connection is re-established.
def on_connection_resumed(connection, return_code, session_present, **kwargs):
    print("Connection resumed. return_code: {} session_present: {}".format(return_code, session_present))

    if return_code == mqtt.ConnectReturnCode.ACCEPTED and not session_present:
        print("Session did not persist. Resubscribing to existing topics...")
        resubscribe_future, _ = connection.resubscribe_existing_topics()

        # Cannot synchronously wait for resubscribe result because we're on the connection's event-loop thread,
        # evaluate result with a callback instead.
        resubscribe_future.add_done_callback(on_resubscribe_complete)


def on_resubscribe_complete(resubscribe_future):
        resubscribe_results = resubscribe_future.result()
        print("Resubscribe results: {}".format(resubscribe_results))

        for topic, qos in resubscribe_results['topics']:
            if qos is None:
                sys.exit("Server rejected resubscribe to topic: {}".format(topic))


# Callback when the subscribed topic receives a message
def on_message_received(topic, payload, **kwargs):
    print("Received message from topic '{}': {}".format(topic, payload))
    global received_count
    received_count += 1
    if received_count == args.count:
        received_all_event.set()

if __name__ == '__main__':
    # Spin up resources
    event_loop_group = io.EventLoopGroup(1)
    host_resolver = io.DefaultHostResolver(event_loop_group)
    client_bootstrap = io.ClientBootstrap(event_loop_group, host_resolver)

    if args.use_websocket == True:
        proxy_options = None
        if (args.proxy_host):
            proxy_options = http.HttpProxyOptions(host_name=args.proxy_host, port=args.proxy_port)

        credentials_provider = auth.AwsCredentialsProvider.new_default_chain(client_bootstrap)
        mqtt_connection = mqtt_connection_builder.websockets_with_default_aws_signing(
            endpoint=args.endpoint,
            client_bootstrap=client_bootstrap,
            region=args.signing_region,
            credentials_provider=credentials_provider,
            websocket_proxy_options=proxy_options,
            ca_filepath=args.root_ca,
            on_connection_interrupted=on_connection_interrupted,
            on_connection_resumed=on_connection_resumed,
            client_id=args.client_id,
            clean_session=False,
            keep_alive_secs=6)

    else:
        mqtt_connection = mqtt_connection_builder.mtls_from_path(
            endpoint=args.endpoint,
            cert_filepath=args.cert,
            pri_key_filepath=args.key,
            client_bootstrap=client_bootstrap,
            ca_filepath=args.root_ca,
            on_connection_interrupted=on_connection_interrupted,
            on_connection_resumed=on_connection_resumed,
            client_id=args.client_id,
            clean_session=False,
            keep_alive_secs=6)

    print("Connecting to {} with client ID '{}'...".format(
        args.endpoint, args.client_id))

    connect_future = mqtt_connection.connect()

    # Future.result() waits until a result is available
    connect_future.result()
    print("Connected!")

    # Subscribe
    print("Subscribing to topic '{}'...".format(args.topic))
    subscribe_future, packet_id = mqtt_connection.subscribe(
        topic=args.topic,
        qos=mqtt.QoS.AT_LEAST_ONCE,
        callback=on_message_received)

    subscribe_result = subscribe_future.result()
    print("Subscribed with {}".format(str(subscribe_result['qos'])))

    # Publish message to server desired number of times.
    # This step is skipped if message is blank.
    # This step loops forever if count was set to 0.
    if args.message:
        if args.count == 0:
            print ("Sending messages until program killed")
        else:
            print ("Sending {} message(s)".format(args.count))

        publish_count = 1
        while (publish_count <= args.count) or (args.count == 0):
            message = "{} [{}]".format(args.message, publish_count)
            print("Publishing message to topic '{}': {}".format(args.topic, message))
            mqtt_connection.publish(
                topic=args.topic,
                payload=message,
                qos=mqtt.QoS.AT_LEAST_ONCE)
            time.sleep(1)
            publish_count += 1

    # Wait for all messages to be received.
    # This waits forever if count was set to 0.
    if args.count != 0 and not received_all_event.is_set():
        print("Waiting for all messages to be received...")

    received_all_event.wait()
    print("{} message(s) received.".format(received_count))

    # Disconnect
    print("Disconnecting...")
    disconnect_future = mqtt_connection.disconnect()
    disconnect_future.result()
    print("Disconnected!")
```

명령줄에서 다음을 실행합니다.

```plainText
python subscribe.py --endpoint a2p6fx7daxxta2-ats.iot.us-east-1.amazonaws.com --cert certificates/548fda031d-certificate.pem.crt --key certificates/548fda031d-private.pem.key --root-ca certificates/root.pem --topic test/testing --message ""
```

값을  기다림.