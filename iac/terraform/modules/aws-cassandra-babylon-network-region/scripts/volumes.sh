#!/bin/bash

set -ex
touch /tmp/volumes-log
echo "Inputs $DEVICE $VOLUME_NAME" >> /tmp/volumes-log
vgchange -ay

#DEVICE=/dev/nvme1n1 for nvm disks


DEVICE_FS=`blkid -o value -s TYPE ${DEVICE} || echo ""`
echo "DEVICE_FS=$DEVICE_FS" /tmp/volumes-log
if [ "`echo -n $DEVICE_FS`" == "" ] ; then 
  # wait for the device to be attached
  DEVICENAME=`echo "${DEVICE}" | awk -F '/' '{print $3}'`

  # loop till the device becomes avaliable.
  while [ ! -e ${DEVICE} ] ; do sleep 1 ; done

  DEVICEEXISTS=''
  while [[ -z $DEVICEEXISTS ]]; do
    echo "checking $DEVICENAME" >> /tmp/volumes-log
    DEVICEEXISTS=`lsblk |grep "$DEVICENAME" |wc -l`
    if [[ $DEVICEEXISTS != "1" ]]; then
      sleep 15
    fi
  done
  pvcreate ${DEVICE}
  vgcreate ${VOLUME_NAME} ${DEVICE}
  lvcreate --name volume1 -l 100%FREE ${VOLUME_NAME}
  mkfs.ext4 /dev/${VOLUME_NAME}/volume1
fi
mkdir -p /${VOLUME_NAME}
echo '/dev/${VOLUME_NAME}/volume1 /${VOLUME_NAME} ext4 defaults 0 0' >> /etc/fstab
mount /${VOLUME_NAME}
chown radix:radix /${VOLUME_NAME}
