airtime-pie-chart
=================

Airtime Pie Chart is a tool to evaluate used airtime of IEEE 802.11 / WiFi
stations and illustrate them in a Pie Chart.

This tool has been created as part of the fair airtime scheduling research
at Open-Mesh Inc.

![example pie chart](/doc/fq_codel_fair.png "Airtime spent sending to a client")

Compilation
-----------

airtime_analyzer depends on:

 * libpcap development files

airtime-pie-chart depends on:

 * GNU R

To compile airtime_analyzer, simply type:

    make

 
Capture WiFi input data
-----------------------

A monitor interface has to be created to capture the radiotap information
for each packet. Make sure that network manager is disabled before trying
to create this device

    iw phy phy0 interface add mon type monitor flags control
    ip link set up dev mon

Make sure that no other tool converted the new monitor interface back to
a managed interface:

    iw dev

Set the correct channel and channel width

    iw dev mon set channel 11 HT20

Capture the radiotap information and the start of the packets

    tcpdump -i mon -s 200 -w aircap.pcap

The capture can be stopped at any time via CTRL+C


Analyze the pcap file
---------------------

The airtime_analyzer can parse the airtime.pcap and calculate for each
mac address how much time was spend sending it traffic. This
data should be stored in a text file to create a pie chart via
airtime-pie-chart.R

    ./airtime_analyzer aircap.pcap > airtime-pie-chart.dat


Generate PIE chart
------------------

The data file generated in the previous step can be send through GNU R
to generate a simple PIE chart:

    R --no-save < airtime-pie-chart.R
    xdg-open airtime-pie-chart.png

Author
------

This software has been written by Sven Eckelmann <sven.eckelmann@open-mesh.com>
for Open-Mesh Inc.

License
-------

airtime_analyzer is licensed under the terms of version 2 of the GNU General
Public License (GPL). Please see the LICENSE file.
