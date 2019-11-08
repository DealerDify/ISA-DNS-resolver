#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <string.h>
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


//site: https://stackoverflow.com/questions/10723403/char-array-to-hex-string-c
//answer: https://stackoverflow.com/a/10723475
char const hex_to_char[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };


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

//funkce pro ziskani stringove reprezentace TYPE v dns odpovedi
const char * get_code_of_dns_type(int type)
{
	switch (type)
	{
	case 1: return "A";
	case 28: return "AAAA";
	case 2: return "NS";
	case 3: return "MD";
	case 4: return "MF";
	case 5: return "CNAME";	
	case 6: return "SOA";	
	case 7: return "MB";	
	case 8: return "MG";	
	case 9: return "MR";	
	case 10: return "NULL";	
	case 11: return "WKS";	
	case 12: return "PTR";	
	case 13: return "HINFO";	
	case 14: return "MINFO";	
	case 15: return "MX";	
	case 16: return "TXT";
	default: return NULL; //other are printed as uknown
	}
}

//funkce pro ziskani stringove reprezentace CLASS v dns odpovedi
const char * get_code_of_dns_class(int type)
{
	switch (type)
	{
	case 1: return "IN";
	case 2: return "CS";
	case 3: return "CH";	
	case 4: return "HS";
	default: return NULL; //unknown
	}
}

//funkce pro ziskani stringove reprezentace REPLY CODE v dns odpovedi
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


//konvertuje ::1 => 0.0.0.0.0.0.....1 (32 cisel)
//pokud je name neplatana ipv6 adresa ukonci program s chybovym kodem 1
std::string name_ip6_to_dots(std::string name)
{
	std::string out;
	uint8_t i6_addr[16];
    if(inet_pton(AF_INET6,name.c_str(),i6_addr))
	{
		for(int i = 0 ; i < 16 ; i ++)
		{//8 bitu rozdeleno na pul a prevedeno na hex
			out+=hex_to_char[i6_addr[i]>>4];
			out+='.';
			out+=hex_to_char[i6_addr[i]&0b00001111];
			out+='.';
		}
		out.pop_back();//smaze tecku na konci
	}
	else
	{
		fprintf(stderr,"Neplatana ipv6 adresa\n");
		exit(1);
	}
    return out;
}

//prevadi ipv4 adresu na adresu pro reverzni dotaz
//napriklad 127.0.0.1 na 1.0.0.127.in-addr.arpa (pokud je ipv6 argument na false)
std::string name_reverse_ip(std::string name, bool ipv6)
{
	std::string out;
	std::vector<std::string> tmp_vec;
	std::string tmp_str;
	for(int i = 0; i < name.length(); i ++)
	{
		if(name[i]=='.')
		{//split po teckach
			tmp_vec.push_back(tmp_str);
			tmp_str="";
			continue;
		}
		tmp_str+=name[i];
	}
	tmp_vec.push_back(tmp_str);
	for(std::vector<std::string>::iterator i = tmp_vec.end(); i-- != tmp_vec.begin(); )
	{//cteme pozpatku a skladame string (otoceni stringu)
		out+=*i;
		out+='.';
		
	}
	if(ipv6)
	{
		out+="ip6.arpa";
	}
	else
	{
		out+="in-addr.arpa";
	}
	return out;
}

//prevadi napriklad www.fit.cz na \3www\3fit\2cz
//name = jmeno na prevod
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
			offset = ((buffer[i]&(0b00111111)) * 256)+(buffer[i+1]&(0b11111111));//offset je za 2 zminenymi jednickami na zbyvajicich 14 bitech
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
	else if(rr_type_int == 5 || rr_type_int == 2 || rr_type_int == 12)
	{//rdata obsahuji jmeno (CNAME nebo NS nebo PTR)
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
	{//rdata jsou vypsana jako hex znaky
		for(int i=*dosavadni_delka_paketu;i<*dosavadni_delka_paketu+rr_rlen_int;i++)
		{
			printf("%x",buffer[i]);//vypis dat v odpovedi		
		}
		printf("\n");
		
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
				if (port_to_ask > 65535 || port_to_ask < 1)
				{	
					fprintf(stderr, "Port ouf of range 1-65535\n");
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
        printf("Sending dns query to: %s\n",inet_ntoa(((struct sockaddr_in *)addr)->sin_addr));
    }
    else if(addr->sa_family==AF_INET6)
    {
        char str[INET6_ADDRSTRLEN];
        printf("Sending dns query to: %s\n",inet_ntop(addr->sa_family,&(((struct sockaddr_in6 *)addr)->sin6_addr),str,INET6_ADDRSTRLEN));
    }
    else
    {
        fprintf(stderr, "Invalid ip address or domain name of server to ask\n");
        exit(-1);
    }

	int dosavadni_delka_paketu = 0;//pomocna promenna urcujici "konec" paketu
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
	{
		if(got_6)
		{
			name_to_resolve=name_ip6_to_dots(name_to_resolve);//ipv6
			name_to_resolve=name_reverse_ip(name_to_resolve,got_6);
		}
		else
		{
			uint8_t i_addr[16];
			if(!inet_pton(AF_INET,name_to_resolve.c_str(),i_addr))
			{//nepodarilo se prevest ipv4 adresu tudiz je neplatna
				fprintf(stderr,"Neplatna ipv4 adresa\n");
				exit(1);
			}
			name_to_resolve=name_reverse_ip(name_to_resolve,got_6); //ipv4
		}
		
	}

	dns_hdr->qdcount=htons(1);//zasilame 1 dotaz
	std::string qname = name_to_len_plus_label(name_to_resolve);
	strncpy(buffer+dosavadni_delka_paketu,qname.c_str(),qname.length());
	dosavadni_delka_paketu+=qname.length()+1;
	struct question *q = (struct question *) (buffer+dosavadni_delka_paketu);
	dosavadni_delka_paketu+=4; // qtype a qclass jsou na 4 bytech (struct question)
	if(got_x)
	{
		q->qtype = htons(12); //typ PTR (reverse query)
	}
	else
	{
		if(got_6)
		{
			q->qtype = htons(28); //typ AAAA - ipv6
		}
		else
		{
			q->qtype = htons(1); //typ A - ipv4
		}
	}
	
	q->qclass = htons(1); //typ IN (the internet)
	
	dns_hdr->flags=htons(dns_hdr->flags);//zbytek casti dns headeru zustava 0
	
	
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
	freeaddrinfo(result);//uvolneni pameti z getaddrinfo
	dosavadni_delka_paketu = 0;
	struct dns_header *dns_hdr_ans = (struct dns_header *) buffer;
	dosavadni_delka_paketu += 12; //dns header zabira 12 bytu
	uint16_t flags = ntohs(dns_hdr_ans->flags);
	int rcode_ans = ntohs(dns_hdr_ans->flags) &0b1111; //posledni 4 bity jsou rcode
	if(flags&(0b0000010000000000)) //vymaskovani AA flagu
	{
		printf("Authoritative: Yes, ");
	}
	else
	{
		printf("Authoritative: No, ");
	}
	if(flags&(0b0000000100000000) && flags&(0b0000000010000000)) //vymaskovani RD a RA flagu
	{//pokud jsou oba zaraz jednalo se o rekurzi
		printf("Recursive: Yes, ");
	}
	else
	{
		printf("Recursive: No, ");
	}
	if(flags&(0b0000001000000000)) //vymaskovani TC flagu
	{
		printf("Truncated: Yes, ");
	}
	else
	{
		printf("Truncated: No, ");
	}

	const char* rcode_ans_str = get_code_of_dns_rcode(rcode_ans);
	if(rcode_ans_str)
	{
		printf("Reply code: %d(%s)\n",rcode_ans,rcode_ans_str);
	}
	else
	{//unknown reply code
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