#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <vector>


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
				exit(-1);
			}
			got_r=true;
		}
		else if (arguments[i] == "-x")
		{
			if(got_x)
			{
				fprintf(stderr, "Opakovane zadane -x\n");
				exit(-1);
			}
			got_x=true;
		}
        else if (arguments[i] == "-6")
		{
			if(got_6)
			{
				fprintf(stderr, "Opakovane zadane -6\n");
				exit(-1);
			}
			got_6=true;
		}
		else if (arguments[i] == "-s")
		{
			if(got_s)
			{
				fprintf(stderr, "Opakovane zadane -s\n");
				exit(-1);
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
				exit(-1);
			}
		}
		else if (arguments[i] == "-p")
		{
			if(got_p)
			{
				fprintf(stderr, "Opakovane zadane -p\n");
				exit(-1);
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
				}
				if (port_to_ask > 65535 || port_to_ask < 0)
				{	
					fprintf(stderr, "Port ouf of range 0-65535\n");
					exit(-1);
				}
				got_p=true;
                i++;
			}
			else
			{
				fprintf(stderr, "Chybi specifikace serveru u -s\n");
				exit(-1);
			}
		}
		else
		{
			if(got_name_to_ask)
			{
				fprintf(stderr, "Opakovane zadana jmeno na ktere se ma program ptat nebo neznamy argument\n");
				exit(-1);
			}
			got_name_to_ask=true;
			name_to_resolve = arguments[i];
		}
	}

	if (!(got_name_to_ask || got_s))
	{
		fprintf(stderr, "Argumenty -s a adrasa jsou povinne\n");
		exit(-1);
	}

	printf("nemam rad linux\n");
	printf("r(rekurze):%d\nx(reverzni):%d\nipv6:%d\nport:%d %d\nserver:%d %s\nadresa na preklad:%s\n",got_r,got_x,got_6,got_p,port_to_ask,got_s,server_to_ask.c_str(),name_to_resolve.c_str());
}