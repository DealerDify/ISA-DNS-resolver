#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <string.h> //memset
#include <vector> //parsovani argumentu
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

struct rr_data
{
	//name reseno mimo struct
	uint16_t type;
	uint16_t cl; //class
	uint32_t ttl;
	uint16_t rdlength;
	//radata reseno mimo struct
};

struct SOA_data
{
	uint32_t serial;
	uint32_t refresh;
	uint32_t retry;
	uint32_t expire;
	uint32_t minimum;
};



//vypise na stderr info o pouziti a skonci s chybovym kodem 1
void wrong_params()
{
	fprintf(stderr,"Usage: dns [-r] [-x] [-6] -s server [-p port] adresa\n");
	fprintf(stderr,"For more info read README\n");
	exit(1);
}

const char * get_code_of_dns_type(int type)
{
	switch (type)
	{
	case 1: return "A";
	case 28: return "AAAA";
	case 2: return "NS";
	case 5: return "CNAME";	
	case 6: return "SOA";	
	case 16: return "TXT";
	default: return NULL; //other are printes as chars
	}
}
const char * get_code_of_dns_class(int type)
{
	switch (type)
	{
	case 1: return "IN";
	case 2: return "CS";
	case 3: return "CH";	
	case 4: return "HS";
	default: return NULL; //not supported class
	}
}

const char * get_code_of_dns_rcode(int type)
{
	switch (type)
	{
	case 0: return "OK";
	case 1: return "Format Error";
	case 2: return "Server failure";
	case 3: return "Name Error";	
	case 4: return "Not implemented";
	case 5: return "Refused";
	default: return NULL; //chyba
	}
}

std::string name_to_len_plus_label(std::string name)
{
	std::string out;
	int cnt = 0;
	for(int i = 0; i < name.length(); i ++)
	{
		if(name[i] == '.')
		{//pokud narazime na tecku zapiseme delku labelu doted precteneho, pred zacatek toho labelu
			out.insert(i-cnt,1,(char)cnt);
            cnt =0;
		}
		else
		{
			cnt++;
			out+=name[i];
		}
	}
    out.insert(name.length()-cnt,1,(char)cnt);//pokud dorazime na konec zapiseme delku labelu mezi teckou a koncem
	return out;
}

//transformuje zapis jmena v paketu na citelnou podobu (vcetne pointeru)
//buffer: buffer cele odpovedi zacinajici dns headerem
//star_offest: odkud se ma zacit cist jmeno
//name_len: vrati zde delku jmena co se precetla z paketu... alias o kolik se potom v bufferu posunout
std::string get_name_from_answer(char *buffer,int start_offset, int *name_len)
{
	if(buffer[start_offset]==0)
	{
		*name_len=1;
		return std::string("root");
	}
	//else
	*name_len = 0;
	std::string name;
	int i = start_offset;
	unsigned int offset = 0;
	while (buffer[i]!=0)
	{
		if(i > start_offset)
		{
			*name_len = i-start_offset;
		}
		if((buffer[i]&0b11000000) ==  0b11000000) //jedna se o pointer (zacina dvema jednickami)
		{
			offset = (buffer[i]&(0b00111111))+(buffer[i+1]&(0b11111111));//offset je za 2 zminenymi jednickami na zbyvajicich 14 bitech
			i = offset;
		}
		else
		{
			name+=(buffer[i]);
			i++;
		}
	}

	//pokud se jednalo o pointer tak pointer je velikosti 16b (2xchar)
	//pokud se jednalo o string tak +1 za zacatek (start_offset a i jsou stejne tj 0, ale precetl se 1 char)
	//                          a jeste +1 za ukoncovaci 0 (skonci while cyklus a uz se nepricte)
	//tj v obrou pripadech +=2
	*name_len +=2;  

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

//vypise info z jednotlivych sekci (answer, additional, authoritative)
void print_info_from_dns_response(char *buffer,int *dosavadni_delka_paketu)
{
	int name_len;
	std::string name_in_answer = get_name_from_answer(buffer,*dosavadni_delka_paketu,&name_len);
	printf("%s",name_in_answer.c_str());
	*dosavadni_delka_paketu+=name_len;
	struct rr_data *rr = (struct rr_data *) (buffer+*dosavadni_delka_paketu);
	*dosavadni_delka_paketu+=10;//mezi name a rdata je 80 bitu... tj posun o 10 bytu

	int rr_type_int = ntohs(rr->type);
	int rr_class_int = ntohs(rr->cl);
	int rr_ttl_int = ntohl(rr->ttl);
	int rr_rlen_int = ntohs(rr->rdlength);
	const char *rr_type_str = get_code_of_dns_type(rr_type_int);

	if(!rr_type_str)
	{//byl vracenu NULL tj nepodporovany typ
		fprintf(stderr,", Unknown type in DNS response: %d",rr_type_int);
	}
	else
	{
		printf(", %s",rr_type_str);//vypis typu v opdovedi
	}

	const char *rr_class_str = get_code_of_dns_class(rr_class_int);
	if(!rr_class_str)
	{//byl vracenu NULL tj nepodporovany typ
		fprintf(stderr,", Unknown class in DNS response: %d\n",rr_class_int);
		exit(1);
	}
	printf(", %s",rr_class_str);//vypis classy v opdovedi
	
	printf(", %d, ", rr_ttl_int);//vypis ttl

	if(rr_type_int == 1)
	{//typ A rdata obsahuji ipv4 adresu
		struct in_addr adresa;
		adresa.s_addr = *(uint32_t*)(buffer+*dosavadni_delka_paketu);
		printf("%s\n",inet_ntoa(adresa));//vypis ipv4 adresy
	}
	else if (rr_type_int == 28)
	{//typ AAAA rdata obsahuji ipv6 adresu
		char src[16];//ipv6 adresa
		memcpy(src,buffer+(*dosavadni_delka_paketu),rr_rlen_int);
		char tmp[INET6_ADDRSTRLEN];//tmp buffer pro inet_ntop funkci
		printf("%s\n",inet_ntop(AF_INET6,src,tmp,INET6_ADDRSTRLEN));
	}
	else if(rr_type_int == 5 || rr_type_int == 2)
	{//rdata obsahuji jmeno (CNAME nebo NS)
		std::string name_in_rdata = get_name_from_answer(buffer,*dosavadni_delka_paketu,&name_len);
		printf("%s\n",name_in_rdata.c_str());//vypis jmena v odpovedi
	}
	else if(rr_type_int == 6)
	{//rdata obsahuji SOA
		int tmp = *dosavadni_delka_paketu;
		std::string mname_in_rdata = get_name_from_answer(buffer,tmp,&name_len);
		printf("\nmname: %s\n",mname_in_rdata.c_str());//vypis m jmena v odpovedi
		tmp+=name_len;//posuv za jmeno
		std::string rname_in_rdata = get_name_from_answer(buffer,tmp,&name_len);
		printf("rname: %s\n",rname_in_rdata.c_str());//vypis r jmena v odpovedi
		tmp+=name_len;//posuv za jmeno
		struct SOA_data *soa = (struct SOA_data*) (buffer+tmp);
		printf("Serial number: %d\n",ntohl(soa->serial));
		printf("Refresh interval: %d s\n",ntohl(soa->refresh));
		printf("Retry interval: %d s\n",ntohl(soa->retry));
		printf("Expire limit: %d s\n",ntohl(soa->expire));
		printf("Minimum TTL: %d s\n",ntohl(soa->minimum));
	}
	else
	{//rdata jsou brana jako text
		std::string string_in_answer;
		for(int i=*dosavadni_delka_paketu;i<*dosavadni_delka_paketu+rr_rlen_int;i++)
		{
			string_in_answer+=buffer[i];		
		}
		printf("%s\n",string_in_answer.c_str());//vypis dat v odpovedi
		
	}
	
	*dosavadni_delka_paketu+=rr_rlen_int;//delka rdat

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

	//printf("r(rekurze):%d\nx(reverzni):%d\nipv6:%d\nport:%d %d\nserver:%d %s\nadresa na preklad:%s\n",got_r,got_x,got_6,got_p,port_to_ask,got_s,server_to_ask.c_str(),name_to_resolve.c_str());
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
	dosavadni_delka_paketu += 12; //dns header zabira 12 bytu
	dns_hdr->id = htons(RANDOM_NUMBER_FOR_ID);
	
	if(got_r)
	{//recursion desired
		dns_hdr->flags |= 0b0000000100000000;//RD flag = 1
	}
	if(got_x)
	{//inverzni dotaz
		dns_hdr->flags |= 0b0000100000000000;//opcode = 1 (inverse query)
		dns_hdr->ancount=htons(1);//zasilame 1 "odpoved"
		dosavadni_delka_paketu+=1; //pridana 1 nula jako "anyname" (root)
		struct rr_data *reverse_q = (struct rr_data*) (buffer+dosavadni_delka_paketu);
		dosavadni_delka_paketu+=10;//mezi name a rdata je 80 bitu... tj posun o 10 bytu
		reverse_q->cl=ntohs(1);//IN
		if(got_6)
		{
			reverse_q->type = htons(28); //typ AAAA ipv6
			reverse_q->rdlength = htons(16); //128 bitu
			struct in6_addr ip6_a;
			if(inet_pton(AF_INET6,name_to_resolve.c_str(),&ip6_a)==0)
			{
				fprintf(stderr,"Invalid ipv6 adress to make inverse query\n");
				exit(-1);
			}
			memcpy(buffer+dosavadni_delka_paketu,&ip6_a,16);
			dosavadni_delka_paketu+=16;
		}
		else
		{
			reverse_q->type = htons(1); //typ A ipv4
			reverse_q->rdlength = htons(4); //32 bitu
			struct in_addr ip_a;
			if(inet_pton(AF_INET,name_to_resolve.c_str(),&ip_a)==0)
			{
				fprintf(stderr,"Invalid ipv4 adress to make inverse query\n");
				exit(-1);
			}
			memcpy(buffer+dosavadni_delka_paketu,&ip_a,4);
			dosavadni_delka_paketu+=4;
		}
		reverse_q->ttl=ntohl(100);//random hodnota... (ttl is not significat viz rfc1035)
		
		
	}
	else
	{//normalni dotaz
		dns_hdr->qdcount=htons(1);//zasilame 1 dotaz
		std::string qname = name_to_len_plus_label(name_to_resolve);
		strncpy(buffer+dosavadni_delka_paketu,qname.c_str(),qname.length());
		dosavadni_delka_paketu+=qname.length()+1;
		struct question *q = (struct question *) (buffer+dosavadni_delka_paketu);//delka dns headeru + delka stringu + \0
		dosavadni_delka_paketu+=4; // qtype a qclass jsou na 4 bytech
		if(got_6)
		{
			q->qtype = htons(28); //typ AAAA ipv6
		}
		else
		{
			q->qtype = htons(1); //typ A ipv4
		}
		q->qclass = htons(1); //typ IN (the internet)
	}
	dns_hdr->flags=htons(dns_hdr->flags);
	//zbytek casti dns headeru zustava 0
	
	
	int sd = socket(addr->sa_family, SOCK_DGRAM, IPPROTO_UDP);
	if(sd < 0)
	{
		fprintf(stderr,"socket() error\n");
		exit(-1);
	}

	struct sockaddr_in *server = (struct sockaddr_in *)addr;
	server->sin_port=htons(port_to_ask);
	socklen_t len;
	if(addr->sa_family==AF_INET6)
	{
		 len = sizeof(struct sockaddr_in6);
	}
	else
	{
		len = sizeof(struct sockaddr_in);
	}
	
	if( sendto(sd,buffer,dosavadni_delka_paketu,0,(struct sockaddr *)server,len)< 0)
	{
		fprintf(stderr,"sendto() error errno:%i\n%s\n",errno,strerror(errno));
		exit(-1);
	}

	alarm(3);//timeout pro odpoved, protoze nemusi prijit...
	signal(SIGALRM, alarm_handler);
	memset(buffer, 0, PCKT_LEN);
	if(recvfrom(sd,buffer,PCKT_LEN,0,(struct sockaddr *)server,&len)< 0)
	{
		fprintf(stderr,"recvfrom() error errno:%i\n%s\n",errno,strerror(errno));
		exit(-1);
	}
	alarm(0);//vypnuti alarmu pokud dosla odpoved
	dosavadni_delka_paketu = 0;
	struct dns_header *dns_hdr_ans = (struct dns_header *) buffer;
	dosavadni_delka_paketu += 12; //dns header zabira 12 bytu
	uint16_t flags = ntohs(dns_hdr_ans->flags);
	int rcode_ans = ntohs(dns_hdr_ans->flags) &0b1111; //posledni 4 bity jsou rcode
	if(flags&(0b0000010000000000)) //vymaskovani AA flagu
	{
		printf("Authority: 1, ");
	}
	else
	{
		printf("Authority: 0, ");
	}
	if(flags&(0b0000001000000000)) //vymaskovani TC flagu
	{
		printf("Truncated: 1, ");
	}
	else
	{
		printf("Truncated: 0, ");
	}
	if(flags&(0b0000000100000000)) //vymaskovani RD flagu
	{
		printf("Recursion desired: 1, ");
	}
	else
	{
		printf("Recursion desired: 0, ");
	}
	if(flags&(0b0000000010000000)) //vymaskovani RA flagu
	{
		printf("Recursion available: 1, ");
	}
	else
	{
		printf("Recursion available: 0, ");
	}
	const char* rcode_ans_str = get_code_of_dns_rcode(rcode_ans);
	if(rcode_ans_str)
	{
		printf("Reply code: %d(%s)\n",rcode_ans,rcode_ans_str);
	}
	else
	{
		printf("Reply code: %d\n",rcode_ans);
	}
	
	printf("\n");


	int pocet_q = ntohs(dns_hdr_ans->qdcount);
	int pocet_ans = ntohs(dns_hdr_ans->ancount);
	int pocet_auth = ntohs(dns_hdr_ans->nscount);
	int pocet_add = ntohs(dns_hdr_ans->arcount);

	printf("Question section(%d)\n",pocet_q);
	if(pocet_q==1)
	{//byl zaslan pouze 1 dotaz (pokud neni v odpovedi, tak nemuze byt vypsan)
		int name_len = 0;
		std::string name_in_question = get_name_from_answer(buffer,dosavadni_delka_paketu,&name_len);
		printf("%s",name_in_question.c_str());
		dosavadni_delka_paketu+=name_len;//posuv za jmeno

		struct question *q_in_response = (struct question *) (buffer + dosavadni_delka_paketu);
		dosavadni_delka_paketu+=4; // qtype a qclass jsou na 4 bytech
		int q_type_int = ntohs(q_in_response->qtype);
		int q_class_int = ntohs(q_in_response->qclass);
		const char *q_type_str = get_code_of_dns_type(q_type_int);

		if(!q_type_str)
		{//byl vracenu NULL tj nepodporovany typ
			fprintf(stderr,", Unknown type in DNS response: %d",q_type_int);
		}
		else
		{
			printf(", %s",q_type_str);//vypis typu v question casti
		}

		const char *q_class_str = get_code_of_dns_class(q_class_int);
		if(!q_class_str)
		{//byl vracenu NULL tj nepodporovany typ
			fprintf(stderr,", Unknown class in DNS response: %d\n",q_class_int);
			exit(1);
		}
		printf(", %s\n",q_class_str);//vypis classy v question casti
	}
	
	

	printf("Answer section(%d)\n",pocet_ans);
	for(int i = 0; i < pocet_ans; i++)
	{
		print_info_from_dns_response(buffer, &dosavadni_delka_paketu);
	}

	printf("Authority section(%d)\n",pocet_auth);
	for(int i = 0; i < pocet_auth; i++)
	{
		print_info_from_dns_response(buffer, &dosavadni_delka_paketu);
	}

	printf("Additional section(%d)\n",pocet_add);
	for(int i = 0; i < pocet_add; i++)
	{
		print_info_from_dns_response(buffer, &dosavadni_delka_paketu);
	}
	
	


}