#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#################################################################################
#
#	from: https://github.com/tiwilliam/fsapi
#
#	requirements:
#		pip3 install FSAPI --user
#
#################################################################################
import os,sys
from fsapi import FSAPI
import paho.mqtt.client as mqtt
import datetime

# ------------- #
# settings      #
# ------------- #
#debug 			= False
debug 			= True

URL = 'http://192.168.2.51:80/device'
PIN = 1234

mqtt_subTopic 	= "smarthome/roberts/action/#"
mqtt_pubTopic 	= "smarthome/roberts/state"

try:
	from configparser import ConfigParser
except ImportError:
	from ConfigParser import ConfigParser  # ver. < 3.0

config = ConfigParser()
config.read('/home/dirk/.credentials/pycredentials') 

#MQTT_SERVER 		= config.get('DEFAULT','mqtt_server')
MQTT_SERVER 		= config.get('DEFAULT','mqtt_serverip')
MQTT_PORT 		= config.get('DEFAULT','mqtt_port')
MQTT_TLS 		= config.get('DEFAULT','mqtt_tls')
MQTT_SERVERIP 	= config.get('DEFAULT','mqtt_serverip')
MQTT_CACERT 		= config.get('DEFAULT','mqtt_cacert')
MQTT_USER 		= config.get('DEFAULT','mqtt_user')
MQTT_PASSWD 		= config.get('DEFAULT','mqtt_passwd')

def log(message): 
	if (debug == True):
		print('%s - %s' % (str(datetime.datetime.now()), message))

# ------------- #       
# mosquitto 		#
# ------------- #  
# The callback for when the client receives a CONNACK response from the server.
def on_connect(client, userdata, flags, rc):
	log("Connected to mosquitto server with result code "+str(rc))
	# Subscribing in on_connect() means that if we lose the connection and
	# reconnect then subscriptions will be renewed.
	client.subscribe(mqtt_subTopic)


def on_disconnect(client, userdata, rc):
	if rc != 0:
		log("Unexpected disconnection."+str(rc))

def on_log(client, userdata, level, buf):
	if not userdata == None:
		log("%s - %s" % (userdata, buf))

def getMqttPublishTopic(topic):
#	if not fs.friendly_name == None:
#		return '%s/%s/%s' % (mqtt_pubTopic, fs.friendly_name, topic)
#		return '%s/%s' % (mqtt_pubTopic, topic)
#	else:	
		return '%s/%s' % (mqtt_pubTopic, topic)

# The callback for when a PUBLISH message is received from the server.
def on_message(client, userdata, msg):

	try: # decode byte to string
		message = str(msg.payload, 'utf-8')
	except Exception as e:
		log(e)
		pass
	log("Topic: %s - Message: <%s> [%s]" % (msg.topic, str(msg.payload), message))

	##########################################
	# power
	if "/power/set" in msg.topic:
		log('power.set: %s' % (message,))
		if message == 'on':
			log('Powering: on')
			fs.power = True
		if message == 'off':
			log('Powering: off')
			fs.power = False

	##########################################
	# mute
	if "/mute/set" in msg.topic:
		log('mute.set: %s' % (message,))
		if message == 'on':
			log('Mute: on')
			fs.mute = True
		if message == 'off':
			log('Mute: off')
			fs.mute = False

	if "/mute/get" in msg.topic:
		log('mute.get: %s' % fs.mute)
		client.publish(getMqttPublishTopic('mute'), fs.mute)

	##########################################
	# modes: 0: 'internet',1: 'spotify',2: 'music',3: 'dab',4: 'fm',5: 'aux',
	if "/mode/set" in msg.topic:
		fs_mode = message
		log('mode.set: %s' % fs_mode)
		if fs_mode in fs.RW_MODES.values():
			log('switching to Mode: %s' % fs_mode)
			try:
				fs.mode = fs_mode
			except Exception as e:
				log(e)    
		else:
			log("error: Mode '%s' unknown" % message)

	if "/mode/get" in msg.topic:
		log('mode.get: %s' % fs.mode)
		client.publish(getMqttPublishTopic('mode'), fs.mode)

	##########################################
	# volume
	if "/volume/set" in msg.topic:
		fs_volume = int(message)
		log('volume.set: %s' % fs_volume )
		if message and fs_volume > -1 and fs_volume < 20: 
			try:
				fs.volume = fs_volume 
				log('Volume is now: %d' % fs_volume )
			except Exception as e:
				log(e)    

	if "/volume/get" in msg.topic:
		log('volume.state: %s' % fs.volume)
		client.publish(getMqttPublishTopic('volume'), fs.volume)

	##########################################
	# status
	if "/current/get" in msg.topic:
		log('current.get: %s - %s - %s' % (fs.play_status, fs.play_info_name, fs.play_info_text))
		json = '{"status":%s,"info_name":%s,"info_text":%s}' % (fs.play_status, fs.play_info_name, fs.play_info_text)
		client.publish(getMqttPublishTopic('current'), json)

	if "/device/get" in msg.topic:
		log('device.get: %s (%s)' % (fs.friendly_name, fs.version))
		json = '{"name":%s,"version":%s}' % (fs.friendly_name, fs.version)
		client.publish(getMqttPublishTopic('device'), json)


########################################################################
#
#   Main Program
#
def main():
	log("connecting to mqtt ...")
	if (MQTT_TLS == "True"):
		log("using tls")
		client.tls_set(MQTT_CACERT)
		client.tls_insecure_set(True)     # prevents error - ssl.SSLError: Certificate subject does not match remote hostname.

	client.on_connect 		= on_connect
	client.on_disconnect 	= on_disconnect
	client.on_log			= on_log
	client.on_message 		= on_message

	client.will_set(mqtt_pubTopic + 'LWT', 'OFF', 0, False)

	client.username_pw_set(username=MQTT_USER,password=MQTT_PASSWD)
	client.connect(MQTT_SERVER, int(MQTT_PORT), 60)
	log("connected.")

	client.will_set(mqtt_pubTopic + 'LWT', 'ON', 0, False)
	log("MQTT LWT published!")

	# Blocking call that processes network traffic, dispatches callbacks and
	# handles reconnecting.
	# Other loop*() functions are available that give a threaded interface and a
	# manual interface.
	client.loop_forever()


if __name__ == '__main__':

	try:
	#	fs = FSAPI('http://192.168.2.51:80/device', 1234)
		fs = FSAPI(URL, PIN)
		if not fs == None:
			log('Name: %s' % fs.friendly_name)
			log('Version: %s' % fs.version)
			log('Mute: %s' % fs.mute)
			log('Mode: %s' % fs.mode)
			log('Power: %s' % fs.power)
			log('Volume: %s' % fs.volume)
			log('Play status: %s' % fs.play_status)
			log('Track name: %s' % fs.play_info_name)
			log('Track text: %s' % fs.play_info_text)
	except Exception as e:
		log(e)
		sys.exit(e)
 
	# https://pypi.org/project/paho-mqtt/
	# create the MQTT client
	try:
		client = mqtt.Client(client_id="fsapi2mqtt", clean_session=True, userdata=None)
	except Exception as e:
		log(e)
		sys.exit(e)

	try:
		main()
	except KeyboardInterrupt:
		pass

	try:
		client.unsubscribe(mqtt_subTopic)
		pass
		client.disconnect()
	except Exception as e:
		log(e)

	print("\nGoodbye!")

