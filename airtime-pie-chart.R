# SPDX-License-Identifier: CC0-1.0
# SPDX-FileCopyrightText: 2013-2016, Sven Eckelmann <ssven.eckelmann@open-mesh.com>

png("airtime-pie-chart.png");
data <- read.table("airtime-pie-chart.dat", header=TRUE);

## when having more clients and only some of them should be labelled
#lbls <- c("02:ba:da:ff:01:00", "02:ba:da:ff:02:00", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "02:ba:da:ff:30:00")
#pie(data$msec, labels = lbls, main="Airtime spent sending to a device")

pie(data$msec, main="Airtime spent sending to a device")
dev.off();
