
�ػ�����

��������: iot_daemon -s /dev/ttyACM0 aaaa::1/64

�ɹ������ػ�������Ҫlinux /devĿ¼�д�����Ӧ���豸�ļ���һ��Ϊ"-s"��ָ����slip�ӿ��豸������һΪ���������豸----tun.
"-s"��ָ����slip�ӿ��豸Ҫ����ʵ�����ָ������slip�ӿ��豸ΪUSB�豸ʱ���豸����ΪttyACM0����slip�ӿ��豸ΪRS232����
�豸�ǣ���S3C2440 ARM�����е��豸����Ϊs3c2410_serialX�����������豸"tun"��Ҫ�����/dev/netĿ¼�У���"tun"�豸������
ʱ��ͨ������tun.ko�ں�ģ����Ӹ��豸�ļ�������Ϊ"insmod /lib/modules/tun.ko"��

�ػ������ΪЭ������IOT�豸�ṩslipͨ�Žӿڡ���Linux�ڽ�����Ӧ�����������豸֮�⣬����Ϊ��̨�������(�ֻ��͵����ϵ�)
��TR069��������ȿͻ��������TCP�����������ػ������ڲ�Ϊÿһ�ֿͻ��˷ֱ��ṩ��һ�������ļ����˿ڣ��˿ڷ������������ʾ��
TR069_SERVER_PORT4	5222	//for tr069 proxier 
MPBMS_SERVER_PORT4	5225	//for mobile phone background managment software
PCBMS_SERVER_PORT4	5226	//for pc background managment software



