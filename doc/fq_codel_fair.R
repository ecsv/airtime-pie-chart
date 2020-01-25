# SPDX-License-Identifier: CC0-1.0
# SPDX-FileCopyrightText: 2013-2016, Sven Eckelmann <ssven.eckelmann@open-mesh.com>

png("fq_codel_fair.png", width = 520, height = 480);
data <- read.table("fq_codel_fair.txt", header=TRUE);

lbls <- c("02:ba:da:ff:01:00", "02:ba:da:ff:02:00", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "02:ba:da:ff:30:00")

pie(data$msec, labels = lbls, main="Airtime spent sending to a client")

dev.off();
