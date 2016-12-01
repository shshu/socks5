all: server.c
	gcc -lpthread -o server server.c
	
clean:
	$(RM) server
