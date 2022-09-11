NAME=popcl
CC=g++
FLAGS= -std=c++11 -pedantic -Wextra -Wall

all:
	$(CC) $(FLAGS) $(NAME).cpp -o $(NAME) -lcrypto -lssl

clean:
	rm $(NAME)
