#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void win() {
    system("cat /flag/flag.txt");
    exit(0);
}

void dummy() {
    printf("Hello World from Dummy\n");
}

void vuln() {
    char buffer[128];
    
    printf("Give me an input: ");
    fflush(stdout);
    
    fgets(buffer, sizeof(buffer), stdin);
    printf(buffer);
    
    printf("\ngive me more data: ");
    fflush(stdout);
    
    fgets(buffer, sizeof(buffer), stdin);
}

int main() {
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);
    
    vuln();
    
    dummy();
    
    return 0;
}
