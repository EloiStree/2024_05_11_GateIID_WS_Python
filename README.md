# GateIID_WS_Python
This Python script is a gate that allows to communicate with IID WS RSA Tunneling Server

This tool  is directly linked this repository:
https://github.com/EloiStree/2024_04_04_IndexIntegerDateTunnelingRSA

This Gate allows to send and receive integer with a linked date to a websocket server  that is host to be a bridge between several devices.

This git is a python version of a gate.

It is called a gate because it hold your RSA Key and allows to push from less complexe code on your network the integer.

This code when execute:
- is a client websocket of the server IID WS RSA Tunneling
- is a local websocket server to connect from javacsript on webpage
- is a udp server to push on integer value
- is a broadcaster of your other device integer change via UDP

It is separated of the main git to be more easily drop in usb key and system that require a gate with python only.

