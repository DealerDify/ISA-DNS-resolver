#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <string.h> //memset
#include <vector>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h> //pro preklad domenoveho jmena serveru DNS
#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h> // alarm
#include <unistd.h> // alarm



#define PCKT_LEN 65507 //mela by byt maximalni mozna delka udp (pravdepodobne plati jen na ipv4)
#define RANDOM_NUMBER_FOR_ID 4560

void alarm_handler(int sig)
{
	printf("Vyprsel cekaci cas na odpoved\n");
	exit(1);
}

struct dns_header
{
	uint16_t id; //id
	uint16_t flags; //flagy
	/*flagy:
	* 1bit QR
	* 4bity OPCODE
	* 1bit AA
	* 1bit TC
	* 1bit RD
	* 1bit RA
	* 3bity zero
	* 3bity RCODE
	*/
	uint16_t qdcount; //pocet v: question section
	uint16_t ancount; //pocet v: answer section
	uint16_t nscount; //pocet v: authority records section
	uint16_t arcount; //pocet v: addional records section
};

struct question
{
	//+qname reseno mimo struct
	uint16_t qtype;
	uint16_t qclass;
};



//vypise na stderr info o pouziti a skonci s chybovym kodem 1
void wrong_params()
{
	fprintf(stderr,"Usage: dns [-r] [-x] [-6] -s server [-p port] adresa\n");
	fprintf(stderr,"For more info read README\n");
	exit(1);
}

//transformuje zapis jmena v paketu na citelnou podobu (vcetne pointeru)
//buffer: buffer cele odpovedi zacinajici dns headerem
//star_offest: odkud se ma zacit cist jmeno
std::string get_name_from_answer(char *buffer,int start_offset)
{
	std::string name;
	int i = start_offset;
	unsigned int offset = 0;
	while (buffer[i]!=0)
	{
		if((buffer[i]&0b11000000) ==  0b11000000) //jedna se o pointer (zacina dvema jednickami)
		{
			offset = (buffer[i]&(0b00111111))+buffer[i+1];//offset je za 2 zminenymi jednickami na zbyvajicich 14 bitech
			i = offset;
		}
		else
		{
			name+=(buffer[i]);
			i++;
		}
	}

	//prevod z delka+znaky na citelnou adresu
	//napriklad z "\3www\5vutbr\2cz" na "www.vutbr.cz" 
	std::string final_name;
	int j = name[0];
	for(int i = 1; i<name.size();i++)
	{
		if(j>0)
		{
			final_name+=name[i];
			j--;
		}
		else
		{
			j=name[i];
			final_name+='.';
		}
	}
	return final_name;	
}

int main(int argc, char **argv)
{
//---------------------------------------ARGUMENTS PARSE-----------------------------------------
	std::vector<std::string> arguments(argv, argv + argc);
	std::string server_to_ask;
	std::string name_to_resolve;
    bool got_name_to_ask=false;
	bool got_r=false;
	bool got_x=false;
	bool got_6=false;
	bool got_p=false;
    bool got_s=false;
    int port_to_ask=53;
	for (std::size_t i=1; i < arguments.size() ; i++)
	{
		if (arguments[i] == "-r")
		{
			if(got_r)
			{
				fprintf(stderr, "Opakovane zadane -r\n");
				wrong_params();
			}
			got_r=true;
		}
		else if (arguments[i] == "-x")
		{
			if(got_x)
			{
				fprintf(stderr, "Opakovane zadane -x\n");
				wrong_params();
			}
			got_x=true;
		}
        else if (arguments[i] == "-6")
		{
			if(got_6)
			{
				fprintf(stderr, "Opakovane zadane -6\n");
				wrong_params();
			}
			got_6=true;
		}
		else if (arguments[i] == "-s")
		{
			if(got_s)
			{
				fprintf(stderr, "Opakovane zadane -s\n");
				wrong_params();
			}
			if ((i + 1) < arguments.size())
			{
				server_to_ask = arguments[i + 1];
				got_s=true;
                i++;
			}
			else
			{
				fprintf(stderr, "Chybi specifikace serveru u -s\n");
				wrong_params();
			}
		}
		else if (arguments[i] == "-p")
		{
			if(got_p)
			{
				fprintf(stderr, "Opakovane zadane -p\n");
				wrong_params();
			}
			if ((i + 1) < arguments.size())
			{
				try
				{
					port_to_ask = std::stoi(arguments[i + 1]);
				}
				catch(const std::exception& e)
				{
					fprintf(stderr,"Za parametrem -p musi nasledovat cislo portu");
					wrong_params();
				}
				if (port_to_ask > 65535 || port_to_ask < 0)
				{	
					fprintf(stderr, "Port ouf of range 0-65535\n");
					wrong_params();
				}
				got_p=true;
                i++;
			}
			else
			{
				fprintf(stderr, "Chybi specifikace serveru u -s\n");
				wrong_params();
			}
		}
		else
		{
			if(got_name_to_ask)
			{
				fprintf(stderr, "Opakovane zadana jmeno na ktere se ma program ptat nebo neznamy argument\n");
				wrong_params();
			}
			got_name_to_ask=true;
			name_to_resolve = arguments[i];
		}
	}

	if (!(got_name_to_ask || got_s))
	{
		fprintf(stderr, "Argumenty -s a adrasa jsou povinne\n");
		wrong_params();
	}

	printf("r(rekurze):%d\nx(reverzni):%d\nipv6:%d\nport:%d %d\nserver:%d %s\nadresa na preklad:%s\n",got_r,got_x,got_6,got_p,port_to_ask,got_s,server_to_ask.c_str(),name_to_resolve.c_str());
//---------------------------------------END-ARGUMENTS PARSE-END-----------------------------------------


/*--------------------------------------------------------------------------------
 *Z manualovyh stranek getaddrinfo
--------------------------------------------------------------------------------*/
    struct addrinfo hints;
    struct addrinfo *result;
	memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;

    if (getaddrinfo(server_to_ask.c_str(),NULL , &hints, &result) != 0)
	{
		fprintf(stderr, "Invalid ip address or domain name of server to ask\n");
        exit(-1);
	}
    struct sockaddr *addr = result->ai_addr;

    if(addr->sa_family==AF_INET)
    {
        printf("Server to ask has ipv4: %s resolved: %s\n", server_to_ask.c_str(),inet_ntoa(((struct sockaddr_in *)addr)->sin_addr));
    }
    else if(addr->sa_family==AF_INET6)
    {
        char str[INET6_ADDRSTRLEN];
        printf("Server to ask has ipv6: %s resolved: %s\n", server_to_ask.c_str(),inet_ntop(addr->sa_family,&(((struct sockaddr_in6 *)addr)->sin6_addr),str,INET6_ADDRSTRLEN));
    }
    else
    {
        fprintf(stderr, "Invalid ip address or domain name of server to ask\n");
        exit(-1);
    }

	int dosavadni_delka_paketu = 0;
	char buffer[PCKT_LEN];
	memset(buffer, 0, PCKT_LEN);

	struct dns_header *dns_hdr = (struct dns_header *) buffer;
	dosavadni_delka_paketu += sizeof(struct dns_header);
	dns_hdr->id = htons(RANDOM_NUMBER_FOR_ID);
	dns_hdr->qdcount=htons(1);//zasilame 1 dotaz
	if(got_r)
	{//recursion desired
		dns_hdr->flags |= 0b0000000100000000;//RD flag = 1
	}
	dns_hdr->flags=htons(dns_hdr->flags);
	//zbytek casti dns headeru zustava 0

	char * qname = "\3www\6google\3com";
	strncpy(buffer+dosavadni_delka_paketu,qname,strlen(qname));
	dosavadni_delka_paketu+=strlen(qname) +1;
	struct question *q = (struct question *) (buffer+dosavadni_delka_paketu);//delka dns headeru + delka stringu + \0
	dosavadni_delka_paketu+=sizeof(struct question);
	q->qtype = htons(1); //typ A (a host adress)
	q->qclass = htons(1); //typ IN (the internet)
	
	int sd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if(sd < 0)
	{
		fprintf(stderr,"socket() error\n");
		exit(-1);
	}

	struct sockaddr_in *server = (struct sockaddr_in *)addr;
	server->sin_port=htons(port_to_ask);
	
	socklen_t len = sizeof(struct sockaddr_in);
	//printf("sd:%d\nbuffer:%d\ndelka:%d\nadresa:%s\n",sd,buffer,dosavadni_delka_paketu,inet_ntoa(server->sin_addr));
	if( sendto(sd,buffer,dosavadni_delka_paketu,0,(struct sockaddr *)server,len)< 0)
	{
		fprintf(stderr,"sendto() error errno:%i\n%s\n",errno,strerror(errno));
		exit(-1);
	}

	alarm(3);//timeout pro udp... protoze nemusi prijit odpoved
	signal(SIGALRM, alarm_handler);
	memset(buffer, 0, PCKT_LEN);
	if(recvfrom(sd,buffer,PCKT_LEN,0,(struct sockaddr *)server,&len)< 0)
	{
		fprintf(stderr,"recvfrom() error errno:%i\n%s\n",errno,strerror(errno));
		exit(-1);
	}
	dosavadni_delka_paketu = 0;
	struct dns_header *dns_hdr_ans = (struct dns_header *) buffer;
	dosavadni_delka_paketu += sizeof(struct dns_header);
	uint16_t flags = ntohs(dns_hdr_ans->flags);
	if(flags&(0b0000010000000000)) //vymaskovani AA flagu
	{
		printf("AA: 1, ");
	}
	else
	{
		printf("AA: 0, ");
	}
	if(flags&(0b0000001000000000)) //vymaskovani TC flagu
	{
		printf("TC: 1, ");
	}
	else
	{
		printf("TC: 0, ");
	}
	if(flags&(0b0000000100000000)) //vymaskovani RD flagu
	{
		printf("RD: 1, ");
	}
	else
	{
		printf("RD: 0, ");
	}
	if(flags&(0b0000000010000000)) //vymaskovani RA flagu
	{
		printf("RA: 1, ");
	}
	else
	{
		printf("RA: 0, ");
	}
	printf("\n");
	printf("Question section(%d)\n",ntohs(dns_hdr_ans->qdcount));
	std::string a = get_name_from_answer(buffer,dosavadni_delka_paketu);
	printf("%s\n",a.c_str());
	printf("Answer section(%d)\n",ntohs(dns_hdr_ans->ancount));
	printf("Authority section(%d)\n",ntohs(dns_hdr_ans->nscount));
	printf("Additional section(%d)\n",ntohs(dns_hdr_ans->arcount));
	
	dosavadni_delka_paketu+=a.length()+2; //+2 protoze end of string a puvodni cislo pred zacatkem jmena
	dosavadni_delka_paketu+=sizeof(struct question);
	std::string b = get_name_from_answer(buffer,dosavadni_delka_paketu);
	printf("string: %s\n",b.c_str());
}