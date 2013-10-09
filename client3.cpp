/*client.cpp*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

//header files for the stream socket
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include<iostream>
#include <arpa/inet.h>

//header file for gmp package
#include<gmp.h>

#include<malloc.h>
#include<math.h>
#include<string.h>

//defining the rotate left and rotate right functions used in SHA1
#define rotateleft(x,n) ((x<<n) | (x>>(32-n)))  
#define rotateright(x,n) ((x>>n) | (x<<(32-n)))  


// the port client will be connecting to                                     
#define PORT "3491" 

#define MAXSIZE 150
#define MAXDATASIZE 100  

using namespace std;

//declaring the SHA1 function
void SHA1(char*a,unsigned long int &b,unsigned long int &c,unsigned long int &d,unsigned long int &e,unsigned long int &f);

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

/************************************************main function****************************************/
int main(int argc, char *argv[])
{
    char g0char[243],g1char[243],g2char[243],g3char[243],g4char[243];
    unsigned long int h0,h1,h2,h3,h4;
    char mstr[MAXSIZE];
    int sockfd, numbytes;  
    char buf1[MAXDATASIZE],buf[245];
    struct addrinfo hints, *servinfo, *p;
    int rv;
    char s[INET6_ADDRSTRLEN];

    if (argc != 2) {
        fprintf(stderr,"usage: client hostname\n");
        exit(1);
    }

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((rv = getaddrinfo(argv[1], PORT, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    // loop through all the results and connect to the first we can
    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                p->ai_protocol)) == -1) {
            perror("client: socket");
            continue;
        }

        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("client: connect");
            continue;
        }

        break;
    }

    if (p == NULL) {
        fprintf(stderr, "client: failed to connect\n");
        return 2;
    }

    inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr),
            s, sizeof s);
    printf("client: connecting to %s\n", s);

    freeaddrinfo(servinfo); // all done with this structure

   //receiving n 
   if ((numbytes = recv(sockfd, buf,250, 0)) == -1) {
        perror("recv");
        exit(1);
     }

    buf[numbytes] = '\0';
    
    printf("client: received '%s'\n",buf);
    //receiving n    
    if ((numbytes = recv(sockfd, buf1, MAXDATASIZE-1, 0)) == -1) {
        perror("recv");
        exit(1);
    }
    
    buf1[numbytes] = '\0';
mpz_t e,n;
mpz_init_set_str(e,buf1,10);
mpz_init_set_str(n,buf,10);
 
//opening the input file
FILE *fp3;
   if((fp3=fopen("input","r"))==NULL)
   {
     printf("cannot open file\n");
     exit(1);
    }

int noofbytes;

//seeking the pointer to the end of file
fseek(fp3,0,SEEK_END);

//reading the total bytes
noofbytes=ftell(fp3);
 
noofbytes=noofbytes/50;

//sending the total number of packets
if (send(sockfd,(char*)&noofbytes,sizeof noofbytes, 0) == -1)
perror("send");
fclose(fp3);
 
//opening the input file in read mode
FILE *fp;
   if((fp=fopen("input","r"))==NULL)
   {
     printf("cannot open file\n");
     exit(1);
    }

//opening the buffer file in write mode
 FILE *fp2;
 if((fp2=fopen("buffer1","w"))==NULL)
   {
  printf("cannot open file\n");
  exit(1);
  
  }
   
while(!feof(fp))
{
  int i=0;
  char ch;
  for(int i=0;i<159;i++)
   mstr[i]=' ';

 int j=0,temp,digex[3];
 
 while(!feof(fp) && i<50 && j<MAXSIZE)
 {
  
  //reading character by character from the file
  ch=getc(fp);
  temp=(int)ch;
   
  //converting into ascii
  for(int k=0;k<3;k++)
   {
     digex[k]=(temp%10)+48;
     temp=temp/10;
   }
 mstr[j++]=(char)digex[2];
 mstr[j++]=(char)digex[1];
 mstr[j++]=(char)digex[0];
if(feof(fp)){mstr[j-1]=' ';
 mstr[j-2]=' ';
 mstr[j-3]=' ';
}
i++;
}

mpz_t m;
mpz_init_set_str(m,mstr,10);
char mstr2[150];
for(int i=0;i<150;i++) 
mstr2[i]=mstr[i];

//calling the SHA1 function
if(feof(fp))
break;
SHA1(mstr2,h0,h1,h2,h3,h4);

//encrypting the message block
mpz_t c;
mpz_init(c);
mpz_powm(c,m,e,n);
mpz_out_str(fp2,10,c);
putc('\n',fp2);
char cchar[243];
char *a=mpz_get_str(cchar,10,c);

//sending the encrypted message block
if (send(sockfd,a,sizeof cchar-1, 0) == -1)
perror("send");


//encrypting the signature blocks
mpz_t g0,g1,g2,g3,g4;
mpz_init(g0);
mpz_init(g1);
mpz_init(g2);
mpz_init(g3);
mpz_init(g4);
mpz_set_ui(g0,h0);
mpz_set_ui(g1,h1);
mpz_set_ui(g2,h2);
mpz_set_ui(g3,h3);
mpz_set_ui(g4,h4);
mpz_powm(g0,g0,e,n);
mpz_powm(g1,g1,e,n);
mpz_powm(g2,g2,e,n);
mpz_powm(g3,g3,e,n);
mpz_powm(g4,g4,e,n);

mpz_get_str(g0char,10,g0);
mpz_get_str(g1char,10,g1);
mpz_get_str(g2char,10,g2);
mpz_get_str(g3char,10,g3);
mpz_get_str(g4char,10,g4);


//sending the signature blocks
if(send(sockfd,(char*)&g0char,(sizeof g0char)-1,0)==-1)
perror("send");
if(send(sockfd,(char*)&g1char,(sizeof g1char)-1,0)==-1)
perror("send");
if(send(sockfd,(char*)&g2char,(sizeof g2char)-1,0)==-1)
perror("send");
if(send(sockfd,(char*)&g3char,(sizeof g3char)-1,0)==-1)
perror("send");
if(send(sockfd,(char*)&g4char,(sizeof g4char)-1,0)==-1)
perror("send");
char ack;

//receiving the acknowledgement
if ((numbytes = recv(sockfd,(char*)&ack, sizeof ack, 0)) == -1) {
        perror("recv");
        exit(1);
    }
if(ack=='y')
continue;
else break;
}

//closing the file and the socket
fclose(fp);  
close(sockfd);
fclose(fp2);
    return 0;

}

/*************************SHA1 function**************************************/
void SHA1(char * str1,unsigned long int &h0,unsigned long int &h1,unsigned long int &h2,unsigned long int &h3,unsigned long int &h4)
 {
     unsigned long int a,b,c,d,e,f,k,temp;
     
     h0 = 0x67452301;
     h1 = 0xEFCDAB89;
     h2 = 0x98BADCFE;
     h3 = 0x10325476;
     h4 = 0xC3D2E1F0;

     char str[250];
     strncpy((char *)str,(const char *)str1,150);

     int current_length = strlen((const char *)str);
     int original_length = current_length;
     str[current_length] = 0x80;
     str[current_length + 1] = '\0';

     char ic = str[current_length];
     current_length++;

     int ib = current_length % 64;
     if(ib<56)
         ib = 56-ib;
     else
         ib = 120 - ib;

     for(int i=0;i < ib;i++)
      {
         str[current_length]=0x00;
         current_length++;
     }
     str[current_length + 1]='\0';
    int i=0;
     for(i=0;i<6;i++)
     {
         str[current_length]=0x0;
         current_length++;
     }
     str[current_length] = (original_length * 8) / 0x100 ;
     current_length++;
     str[current_length] = (original_length * 8) % 0x100;
     current_length++;
     str[current_length+i]='\0';

     int number_of_chunks = current_length/64;
     unsigned long int word[80];
     for(i=0;i<number_of_chunks;i++)
     {
         for(int j=0;j<16;j++)
         {
             word[j] = str[i*64 + j*4 + 0] * 0x1000000 + str[i*64 + j*4 + 1] * 0x10000 + str[i*64 + j*4 + 2] * 0x100 + str[i*64 + j*4 + 3];
         }
         for(int j=16;j<80;j++)
         {
             word[j] = rotateleft((word[j-3] ^ word[j-8] ^ word[j-14] ^ word[j-16]),1);
         }

         a = h0;
         b = h1;
         c = h2;
         d = h3;
         e = h4;

         for(int m=0;m<80;m++)
         {
             if(m<=19)
             {
                 f = (b & c) | ((~b) & d);
                 k = 0x5A827999;
             }
             else if(m<=39)
             {
                 f = b ^ c ^ d;
                 k = 0x6ED9EBA1;
             }
             else if(m<=59)
             {
                 f = (b & c) | (b & d) | (c & d);
                 k = 0x8F1BBCDC;
             }
             else
             {
                 f = b ^ c ^ d;
                 k = 0xCA62C1D6;
             }

             temp = (rotateleft(a,5) + f + e + k + word[m]) & 0xFFFFFFFF;
             e = d;
             d = c;
             c = rotateleft(b,30);
             b = a;
             a = temp;

         }

         h0 = h0 + a;
         h1 = h1 + b;
         h2 = h2 + c;
         h3 = h3 + d;
         h4 = h4 + e;

     }
 
 }

                         
