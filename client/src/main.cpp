#include <iostream>
#include <cstring>

#include "../inc/client.h"

int main(int argc, char *argv[])
{
	try
	{
		Client c("127.0.0.1", 1234);

		c.SendMessage("Hello, i'm " + std::string(argv[1]));
		auto recv = c.ReceiveMessage();
		if (std::holds_alternative<std::string>(recv))
		{
			std::cout << "Answer: " << std::get<std::string>(recv) << std::endl;
		}
		else
		{
			std::cout << "Receive error with code: " << std::get<int>(recv) << std::endl;
		}
	}
	catch (const std::exception &e)
	{
		std::cerr << e.what() << '\n';
	}

	return 0;
}
