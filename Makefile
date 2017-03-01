#CC = mipsel-openwrt-linux-gcc
#CC = gcc
CC = arm-linux-gcc
TARGET = iot_daemon_SDN
OBJS = iot_daemon.o socket.o
#CFLAGS = -D_REENTRANT -DDEBUG -DDEBUG_PRINT -g -Wall -I/home/zc/openwrt/trunk/staging_dir/target-mipsel_24kec+dsp_musl-1.1.10/usr/include -L/home/zc/openwrt/trunk/staging_dir/target-mipsel_24kec+dsp_musl-1.1.10/usr/lib -lxml2 -lz -lm
CFLAGS = -DDEBUG -g -Wall -I/media/zc/c09e9abb-cb5a-4ea0-8f83-bb7993e99b55/libxml2-2.8.0/include -L/media/zc/c09e9abb-cb5a-4ea0-8f83-bb7993e99b55/libxml2-2.8.0/.libs -lxml2
#CFLAGS =  -D_REENTRANT -DDEBUG -g -Wall -lxml2
RM = rm -f

$(TARGET):$(OBJS)
	$(CC) -o $@ $^ $(CFLAGS) -lpthread 

$(OBJS):%.o:%.c
	$(CC) -c $(CFLAGS) $< -o $@

clean:
	$(RM) $(TARGET) $(OBJS)
