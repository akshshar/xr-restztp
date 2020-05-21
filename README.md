# xr-restztp
Fully automated, Crosswork Based Restful ZTP flow using Classic ZTP with IOS-XR 6.6.3+

## The Basics
xr-restztp is a simple Hook server that implements a REST client for Cisco Crosswork (3.2+) to enable and add ZTP devices, profiles, configs and credentials.
It also hosts a flask based REST server in a thread to listen for POST events from a python script executed by the IOS-XR device that is running ZTP. The python ZTP script itself is uploaded to Cisco Crosswork by the xr-restztp code during the initial set up.

The flow of events is showcased below:

![demo-flow](/demo_flow.gif)
