#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<unistd.h>
#include<net/if.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<netinet/ip.h>
#include<linux/sockios.h>
#include<linux/if_packet.h>
#include<arpa/inet.h>
#include<netinet/if_ether.h>
#include<sys/ioctl.h>
#include<sys/types.h>

unsigned char trans(unsigned char value);
unsigned char getvalue(unsigned char value);
void calvalue1(unsigned char value[4]);
void calvalue2(unsigned char value[4]);
unsigned char ruijieAdd(unsigned char value);


unsigned char heart[45]=		//	心跳包
{
	0x00,0x00,0x00,0x00,0x00,0x00,		//	认证服务器MAC
	0x00,0x00,0x00,0x00,0x00,0x00,		//	认证客户端MAC
	0x88,0x8e,0x01,0xbf,0x00,0x1e,0xff,0xff,0x37,0x77,0x7f,0x9f,
	0x00,0x00,0x00,0x00,		//	0x18-0x19-0x1a-0x1b为value1
	0xff,0xff,0x37,0x77,0x7f,0x9f,
	0x00,0x00,0x00,0x00,		//	0x22-0x23-0x24-0x25为value2
	0xff,0xff,0x37,0x77,0x7f,0x3f,0xff
};


//	netname1是局域网内电脑通过网线连接路由器的网卡;netname2为路由器WAN口到认证服务器的网卡
//	如果程序自用,把下文argv[1]和argv[2]替换成netname1和netname2
//char netname1[]="eth0.1";
//char netname2[]="eth0.2";

unsigned char value1[4] = { 0x00,0x00,0x00,0x00 };
unsigned char value2[4] = { 0x00,0x00,0x00,0x00 };
unsigned char send_value1[4] = { 0x00,0x00,0x00,0x00 };
unsigned char send_value2[4] = { 0x00,0x00,0x00,0x00 };
unsigned char adj_value1[4] = { 0x00,0x00,0x00,0x00 };
unsigned char adj_value2[4] = { 0x00,0x00,0x00,0x00 };


unsigned int responseIDnum=0;
unsigned char responseIDbuf[1024]={0};
unsigned char buf[1024]={0};
unsigned char cMAC[]={0x00,0x00,0x00,0x00,0x00,0x00};


int main(int argc,char* argv[])
{

	if(argc!=3)
	{
		printf("\nmiss argv!  please append with netname1 and netname2.\n");
		exit(0);
	}
	printf("\n本程序作者: 吴壮\n修改: 周洪鑫\n");
	 


	int fd1=0,fd2=0;
	int destlen=0;
	int num=0,i=0;

	fd1=socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
	struct sockaddr_ll dest1;
	struct ifreq ifstruct1;
	strncpy(ifstruct1.ifr_name,argv[1],IFNAMSIZ);		//	第二个参数为路由器连接电脑的网卡名
	ioctl(fd1,SIOCGIFINDEX,&ifstruct1);
	memset(&dest1,0,sizeof(dest1));
	dest1.sll_ifindex=ifstruct1.ifr_ifindex;
	destlen=sizeof(dest1);


	fd2=socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
	struct sockaddr_ll dest2;
	struct ifreq ifstruct2;
	strncpy(ifstruct2.ifr_name,argv[2],IFNAMSIZ);		//	第二个参数为路由器WAN口的网卡名
	ioctl(fd2,SIOCGIFINDEX,&ifstruct2);
	memset(&dest2,0,sizeof(dest2));
	dest2.sll_ifindex=ifstruct2.ifr_ifindex;






//	接收电脑发送的EAP_start
	memset(buf,0,sizeof(buf));
	do
	{
		num=recvfrom(fd1,buf,sizeof(buf),0,NULL,NULL);  
		if((buf[12]==0x88)&&(buf[13]==0x8e)&&(buf[0x0f]==0x01))
		{
			printf("\nget EAP_start,length:%d    MAC:",num); 
			printf("%.2x-%.2x-%.2x-%.2x-%.2x-%.2x\n",buf[6],buf[7],buf[8],buf[9],buf[10],buf[11]);
			cMAC[0]=buf[6];
			cMAC[1]=buf[7];
			cMAC[2]=buf[8];
			cMAC[3]=buf[9];
			cMAC[4]=buf[10];
			cMAC[5]=buf[11];
			break;
		}
		memset(buf,0,sizeof(buf));
	}while(1);



//	转发EAP_start给服务器
	printf("send EAP_start to server:");
	if(sendto(fd2,buf,num,0,(struct sockaddr*)&dest2,destlen)>0)
		printf("---->send Success!\n");
	else
	{
		printf("---->send Failure!\n");
		exit(0);
	}







//	接收服务器发来的requestID包

	do
	{
		num=recvfrom(fd2,buf,sizeof(buf),0,NULL,NULL);  
		if((buf[12]==0x88)&&(buf[13]==0x8e)&&(buf[0]==cMAC[0])&&(buf[1]==cMAC[1])&&(buf[2]==cMAC[2])&&(buf[3]==cMAC[3])&&(buf[4]==cMAC[4])&&(buf[5]==cMAC[5]))
		{
			if(buf[0x16]==0x01)
			{
				printf("get requestID,length:%d   serverMAC:",num),
				printf("%.2x-%.2x-%.2x-%.2x-%.2x-%.2x\n",buf[6],buf[7],buf[8],buf[9],buf[10],buf[11]);
				break;
			}
		}
		memset(buf,0,sizeof(buf));
	}while(1);








//	转发requestID给电脑
	printf("send requestID to client:");
	if(sendto(fd1,buf,num,0,(struct sockaddr*)&dest1,destlen)>0)
		printf("---->send Success!\n");
	else
	{
		printf("---->send Failure!\n");
		exit(0);
	}
	memset(buf,0,sizeof(buf));





//	接收电脑发送的responseID
	do
	{
		num=recvfrom(fd1,buf,sizeof(buf),0,NULL,NULL);  
		if((buf[12]==0x88)&&(buf[13]==0x8e)&&(buf[0x12]==0x02)&&(buf[0x16]==0x01))
		{
			printf("get responseID,length:%d    MAC:",num); 
			printf("%.2x-%.2x-%.2x-%.2x-%.2x-%.2x\n",buf[6],buf[7],buf[8],buf[9],buf[10],buf[11]);
			break;
		}
		memset(buf,0,sizeof(buf));
	}while(1);




//	备份responseID包,服务器会莫名再次要求responseID,需要重传
	memcpy(responseIDbuf,buf,sizeof(buf));
	responseIDnum=num;






//	转发responseID给服务器
	printf("send responseID to server:");
	if(sendto(fd2,buf,num,0,(struct sockaddr*)&dest2,destlen)>0)
		printf("---->send Success!\n");
	else
	{
		printf("---->send Failure!\n");
		exit(0);
	}






//	接收服务器发来的requestMD5包

	memset(buf,0,sizeof(buf));
	do
	{
		num=recvfrom(fd2,buf,sizeof(buf),0,NULL,NULL);  
		if((buf[12]==0x88)&&(buf[13]==0x8e)&&(buf[0]==cMAC[0])&&(buf[1]==cMAC[1])&&(buf[2]==cMAC[2])&&(buf[3]==cMAC[3])&&(buf[4]==cMAC[4])&&(buf[5]==cMAC[5]))
		{
			if(buf[0x16]==0x04)
			{
				printf("get requestMD5,length:%d   serverMAC:",num),
				printf("%.2x-%.2x-%.2x-%.2x-%.2x-%.2x\n",buf[6],buf[7],buf[8],buf[9],buf[10],buf[11]);
				break;
			}
			else if(buf[0x16]==0x01)	//	丢包,服务器要求重传
			{

				printf("requestID again!\n");
				printf("send responseID to server:");
				if(sendto(fd2,responseIDbuf,responseIDnum,0,(struct sockaddr*)&dest2,destlen)>0)
					printf("---->send Success!\n");
				else
				{
					printf("---->send Failure!\n");
					exit(0);
				}
			}
		}
		memset(buf,0,sizeof(buf));
	}while(1);








//	转发requestMD5给电脑
	printf("send requestMD5 to client:");
	if(sendto(fd1,buf,num,0,(struct sockaddr*)&dest1,destlen)>0)
		printf("---->send Success!\n");
	else
	{
		printf("---->send Failure!\n");
		exit(0);
	}
	memset(buf,0,sizeof(buf));







//	接收电脑发送的responseMD5
	do
	{
		num=recvfrom(fd1,buf,sizeof(buf),0,NULL,NULL);  
		if((buf[12]==0x88)&&(buf[13]==0x8e)&&(buf[0x12]==0x02)&&(buf[0x16]==0x04))
		{
			printf("get responseMD5,length:%d    MAC:",num); 
			printf("%.2x-%.2x-%.2x-%.2x-%.2x-%.2x\n",buf[6],buf[7],buf[8],buf[9],buf[10],buf[11]);
			break;
		}
		memset(buf,0,sizeof(buf));
	}while(1);




//	转发responseMD5给服务器
	printf("send responseMD5 to server:");
	if(sendto(fd2,buf,num,0,(struct sockaddr*)&dest2,destlen)>0)
		printf("---->send Success!\n");
	else
	{
		printf("---->send Failure!\n");
		exit(0);
	}



//	接收服务器发来的success包
	do
	{
		num=recvfrom(fd2,buf,sizeof(buf),0,NULL,NULL); 
		if((buf[12]==0x88)&&(buf[13]==0x8e)&&(buf[0]==cMAC[0])&&(buf[1]==cMAC[1])&&(buf[2]==cMAC[2])&&(buf[3]==cMAC[3])&&(buf[4]==cMAC[4])&&(buf[5]==cMAC[5])&&(buf[0x12]==0x03))
		{
			printf("get Success,length:%d    serverMAC:",num); 
			printf("%2x-%2x-%2x-%2x-%2x-%2x\n",buf[6],buf[7],buf[8],buf[9],buf[10],buf[11]);
			break;
		}
		memset(buf,0,sizeof(buf));
	}while(1);







//	转发Success给电脑
	printf("send Success to client:");
	if(sendto(fd1,buf,num,0,(struct sockaddr*)&dest1,destlen)>0)
		printf("---->send Success!\n");
	else
	{
		printf("---->send Failure!\n");
		exit(0);
	}








//	开始捕获电脑发送的心跳包

	do
	{
		num=recvfrom(fd1,buf,sizeof(buf),0,NULL,NULL);  
		if((buf[12]==0x88)&&(buf[13]==0x8e)&&(buf[0x0f]==0xbf))
		{
			printf("capture a heart-beat,length:%d    MAC:",num); 
			printf("%2x-%2x-%2x-%2x-%2x-%2x\n",buf[6],buf[7],buf[8],buf[9],buf[10],buf[11]);
			break;
		}
		memset(buf,0,sizeof(buf));
	}while(1);
	memcpy(heart,buf,sizeof(heart));

	close(fd1);

	//还原value1
	value1[0] = buf[0x18];
	value1[1] = buf[0x19];
	value1[2] = buf[0x1a];
	value1[3] = buf[0x1b];
	//还原value2
	value2[0] = buf[0x22];
	value2[1] = buf[0x23];
	value2[2] = buf[0x24];
	value2[3] = buf[0x25];

	while (1)
	{
		//填充send_value1
		heart[0x18] = value1[0];
		heart[0x19] = value1[1];
		heart[0x1a] = value1[2];
		heart[0x1b] = value1[3];

		//填充send_value2
		heart[0x22] = value2[0];
		heart[0x23] = value2[1];
		heart[0x24] = value2[2];
		heart[0x25] = value2[3];
		//发送心跳包给服务器
		if(i==0)
			printf("send heart-beat to server:");
		if(sendto(fd2,heart,sizeof(heart),0,(struct sockaddr*)&dest2,destlen)<0)
		{
			printf("---->send Failure!\n");
			exit(0);
		}
		if(i==0)
		{
			printf("send Success!---->keeping online!\nYou can quit RuiJie on your computer!\n");
			i=1;
		}

		//用下面的方法调整心跳包
		calvalue1(value1);
		calvalue2(value2);

		sleep(20);
	}
	close(fd2);
	return 0;
}
/*unsigned char trans(unsigned char value)		//	锐捷混淆算法对照表,锐捷的工程师也搞不出什么新花样
{
	switch (value)
	{
	case 0x00:return 0x0f;		//	0<--->f
	case 0x01:return 0x07;		//	1<--->7
	case 0x02:return 0x0b;		//	2<--->b
	case 0x03:return 0x03;		//	3<--->3
	case 0x04:return 0x0d;		//	4<--->d
	case 0x05:return 0x05;		//	5<--->5
	case 0x06:return 0x09;		//	6<--->9
	case 0x07:return 0x01;		//	7<--->1
	case 0x08:return 0x0e;		//	8<--->e
	case 0x09:return 0x06;		//	9<--->6
	case 0x0a:return 0x0a;		//	a<--->a
	case 0x0b:return 0x02;		//	b<--->2
	case 0x0c:return 0x0c;		//	c<--->c
	case 0x0d:return 0x04;		//	d<--->4
	case 0x0e:return 0x08;		//	e<--->8
	case 0x0f:return 0x00;		//	f<--->0
	}
};
unsigned char getvalue(unsigned char value)		//	加密和解密是一个算法,x=f(f(x))
{
	unsigned char h = (value & 0xf0) >> 4;
	unsigned char l = value & 0x0f;
	return (trans(h) << 4) | trans(l);
};
*/
void calvalue1(unsigned char value[4]) {		//心跳包第一段增加
	unsigned char signalvalue1 = value[0];
	unsigned char signalvalue2 = value[1];
	unsigned char signalvalue3 = value[2];
	unsigned char signalvalue4 = value[3];

	//判断是否需要进位
	//执行进位之后返回，防止可能出现的两次计算
	if (signalvalue4 == 0x00){
        signalvalue3 = ruijieAdd(signalvalue3);
        signalvalue4 = ruijieAdd(signalvalue4);
        value1[0] = signalvalue1;
        value1[1] = signalvalue2;
        value1[2] = signalvalue3;
        value1[3] = signalvalue4;
	return;
    }				
        
	if (signalvalue3 == 0x00){
        signalvalue2 = ruijieAdd(signalvalue2);
        signalvalue4 = ruijieAdd(signalvalue4);
        value1[0] = signalvalue1;
        value1[1] = signalvalue2;
        value1[2] = signalvalue3;
        value1[3] = signalvalue4;
        return;
    }
    
	if (signalvalue2 == 0x00){
        signalvalue1 = ruijieAdd(signalvalue1);
        signalvalue4 = ruijieAdd(signalvalue4);
        value1[0] = signalvalue1;
        value1[1] = signalvalue2;
        value1[2] = signalvalue3;
        value1[3] = signalvalue4;
        return;
    }
    
	signalvalue4 = ruijieAdd(signalvalue4);

	value1[0] = signalvalue1;
	value1[1] = signalvalue2;
	value1[2] = signalvalue3;
	value1[3] = signalvalue4;
}

void calvalue2(unsigned char value[4]) {		//心跳包第二段增加
	unsigned char signalvalue1 = value[0];
	unsigned char signalvalue2 = value[1];
	unsigned char signalvalue3 = value[2];
	unsigned char signalvalue4 = value[3];

	//判断是否需要进位
	if (signalvalue4 == 0x00){
        signalvalue3 = ruijieAdd(signalvalue3);
        signalvalue4 = ruijieAdd(signalvalue4);
        value2[0] = signalvalue1;
        value2[1] = signalvalue2;
        value2[2] = signalvalue3;
        value2[3] = signalvalue4;
        return;
    }
        
	if (signalvalue3 == 0x00){
        signalvalue2 = ruijieAdd(signalvalue2);
        signalvalue4 = ruijieAdd(signalvalue4);
        value2[0] = signalvalue1;
        value2[1] = signalvalue2;
        value2[2] = signalvalue3;
        value2[3] = signalvalue4;
        return;
    }
    
	if (signalvalue2 == 0x00){
        signalvalue1 = ruijieAdd(signalvalue1);
        signalvalue4 = ruijieAdd(signalvalue4);
        value2[0] = signalvalue1;
        value2[1] = signalvalue2;
        value2[2] = signalvalue3;
        value2[3] = signalvalue4;
        return;
    }
    
	signalvalue4 = ruijieAdd(signalvalue4);

	value2[0] = signalvalue1;
	value2[1] = signalvalue2;
	value2[2] = signalvalue3;
	value2[3] = signalvalue4;
}

unsigned char ruijieAdd(unsigned char value) {		//心跳包增加算法
	unsigned char result = value;
	unsigned char calTemp;
	int sign = 7;
	for(sign;sign>=0;sign--){
		calTemp = result >> sign;
		if (calTemp == 0x01)
			break;
	}
	if(sign==-1)sign=0;			       //0x00情况的计算
	calTemp = result >> sign;
	calTemp = ~calTemp;
	unsigned char calAssistant = 0xff;
	calAssistant = calAssistant << (8-sign);
	calAssistant = calAssistant >> (8-sign);
	result = (result&calAssistant) + (calTemp<<sign);
	return result;
}
