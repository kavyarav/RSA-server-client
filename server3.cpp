/*server.cpp
*/
/*header file for gmp package*/
#include<gmp.h>

#include<iostream>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

/*header file for socket stream*/
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include<malloc.h>

#include<math.h>
#include<string.h>

/*rotate left and rotate right functions used in SHA1*/
#define rotateleft(x,n) ((x<<n) | (x>>(32-n)))  
#define rotateright(x,n) ((x>>n) | (x<<(32-n)))  

using namespace std;
#define PORT "3491"  // the port users will be connecting to

#define BACKLOG 10     // how many pending connections queue will hold

/*declaring the decrypt function*/
char decrypt(mpz_t,mpz_t,unsigned long int&,unsigned long int &,unsigned long int&,unsigned long int &,unsigned long int& );

void sigchld_handler(int s)
{
    while(waitpid(-1, NULL, WNOHANG) > 0);
}

/*declaring the SHA1 function*/
void SHA1(char*,unsigned long int&,unsigned long int &,unsigned long int&,unsigned long int &,unsigned long int& );

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

//defining the decrytion key (d,n)
mpz_t n,d;

/***************** the main function*********************************************/
int main(void)
{
 
 char h0char[243],h1char[243],h2char[243],h3char[243],h4char[243];
 mpz_t h0,h1,h2,h3,h4;
 unsigned long int g0,g1,g2,g3,g4;
 mpz_init(h0);
 mpz_init(h1);
 mpz_init(h2);
 mpz_init(h3);
 mpz_init(h4);
 
//----------------the key generation-------------------------------

 mpz_t c,e,p,dp,dq,q,limit;
 mpz_init_set_str(limit,"999999999",10);
 mpz_init(p);
 mpz_init(q);
 mpz_init(dp);
 mpz_init(dq);
 
//generating random primes p and q
  gmp_randstate_t state1;
 gmp_randinit_mt(state1);
 gmp_randseed_ui(state1,time(NULL));
 mpz_urandomb(p,state1,400);
 mpz_nextprime(p,p);
 gmp_printf(" p= %Zd\n",p);
 gmp_randstate_t state2;
 gmp_randinit_mt(state2);

 gmp_randseed_ui(state2,time(NULL));
 mpz_urandomb(q,state2+1,400);
 mpz_nextprime(q,q);

//printing p and q
 gmp_printf(" q= %Zd\n",q);
 mpz_init(n);
 mpz_mul(n,p,q);
 gmp_printf("n= %Zd\n",n);

//initializing n and phi 
 mpz_t phi;
 mpz_init(phi);
 mpz_sub_ui(dp,p,1);
 mpz_sub_ui(dq,q,1);
 mpz_mul(phi,dp,dq);
 mpz_t gc;

//initializing the encryption key e
 mpz_init(e);
 mpz_init(gc);
 gmp_randstate_t state3;
 gmp_randinit_mt(state3);
 mpz_urandomm(e,state3,limit);
 do{
 mpz_add_ui(e,e,1);
 mpz_gcd(gc,e,phi);
}while(mpz_cmp_ui(gc,1)!=0);

//printing e
gmp_printf(" e= %Zd\n",e);

//initializing decryption key d
mpz_init(d);
mpz_invert(d,e,phi);
gmp_printf("d =%Zd\n",d);

//converting e,n to char
char echar[10],dchar[100],nchar[250];
char *a1=mpz_get_str(echar,10,e);
char *a2=mpz_get_str(nchar,10,n);
// printing n char and e char
puts(nchar);
puts(echar);
cout<<sizeof echar;
cout<<sizeof nchar;
    int i,numbytes,numbytes1;

//--------------------------creatiing the socket---------------------------   
    int sockfd, new_fd;  // listen on sock_fd, new connection on new_fd
    struct addrinfo hints, *servinfo, *p1;
    struct sockaddr_storage their_addr; // connector's address information
    socklen_t sin_size;
    struct sigaction sa;
    int yes=1;
    char s[INET6_ADDRSTRLEN],buf[243];
    int rv;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE; // use my IP

    if ((rv = getaddrinfo(NULL, PORT, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    // loop through all the results and bind to the first we can
    for(p1 = servinfo; p1 != NULL; p1 = p1->ai_next) {
        if ((sockfd = socket(p1->ai_family, p1->ai_socktype,
                p1->ai_protocol)) == -1) {
            perror("server: socket");
            continue;
        }

        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes,
                sizeof(int)) == -1) {
            perror("setsockopt");
            exit(1);
        }

        if (bind(sockfd, p1->ai_addr, p1->ai_addrlen) == -1) {
            close(sockfd);
            perror("server: bind");
            continue;
        }

        break;
    }

    if (p1 == NULL)  {
        fprintf(stderr, "server: failed to bind\n");
        return 2;
    }

    freeaddrinfo(servinfo); // all done with this structure

    if (listen(sockfd, BACKLOG) == -1) {
        perror("listen");
        exit(1);
    }

    sa.sa_handler = sigchld_handler; // reap all dead processes
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        perror("sigaction");
        exit(1);
    }

    printf("server: waiting for connections...\n");//server waits for connection
    int flag=0;
     
    //opening the output file for writing 
     FILE *fp3;
     if((fp3=fopen("output","w"))==NULL){
         printf("cannot open file");
         exit(1);
           }
      fclose(fp3);

     while(flag==0) {  // main accept() loop
        sin_size = sizeof their_addr;
        new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
        if (new_fd == -1) {
            perror("accept");
            continue;
        }

        inet_ntop(their_addr.ss_family,
            get_in_addr((struct sockaddr *)&their_addr),
            s, sizeof s);
        printf("server: got connection from %s\n", s);
         
        if (!fork()) { // this is the child process
            close(sockfd); // child doesn't need the listener
            
            //sending n and e throught the socket
            if (send(new_fd,a2,sizeof nchar, 0) == -1)
                perror("send");
            if(send(new_fd,a1,sizeof echar,0)==-1)
               perror("send");
          i=0;
        
  //receiving the number of packets  to be received
        int noofbytes;
        if ((numbytes = recv(new_fd,(char*)&noofbytes,sizeof noofbytes, 0)) == -1) {
              perror("recv");
              exit(1);
           }

       

         while(i<noofbytes)           
           {
         //creating the temporary buffer file 
         FILE *fp1;
         if((fp1=fopen("buffer","w"))==NULL){
         printf("cannot open file");
         exit(1);
           }
              

              //receiving the cipher text packet
              if ((numbytes = recv(new_fd,&buf,242, 0)) == -1) {
              perror("recv");
              exit(1);
              
             }
              //receiving the signature part`1
               if ((numbytes1 = recv(new_fd,(char*)h0char,(sizeof h0char)-1, 0)) == -1) {
              perror("recv");
              exit(1);

             }
             //receiving signature part 2
             if ((numbytes1= recv(new_fd,(char*)&h1char,(sizeof h1char)-1, 0)) == -1) {
              perror("recv");
              exit(1);

             }
             //receiving signature part 3
              if ((numbytes1 = recv(new_fd,(char*)&h2char,(sizeof h2char)-1, 0)) == -1) {
              perror("recv");
              exit(1);

             }
             //receiving signature part 4
             if ((numbytes1 = recv(new_fd,(char*)&h3char,(sizeof h3char)-1, 0)) == -1) {
              perror("recv");
              exit(1);

             }
            //receiving signature part 5  
            if ((numbytes1 = recv(new_fd,(char*)&h4char,(sizeof h4char)-1, 0)) == -1) {
              perror("recv");
              exit(1);

             }
             
            
            i++;
             
           
           buf[numbytes] = '\0';
          
         
         //putting the cipher text packet in the temporary buffer
         fputs(buf,fp1);
         putc('\n',fp1); 
          
         //closing the buffer
         fclose(fp1); 
         
         mpz_set_str(h0,h0char,10);
         mpz_set_str(h1,h1char,10);
         mpz_set_str(h2,h2char,10);
         mpz_set_str(h3,h3char,10);
         mpz_set_str(h4,h4char,10);         
       //decrypting the signature parts 
        mpz_powm(h0,h0,d,n);
        mpz_powm(h1,h1,d,n);
        mpz_powm(h2,h2,d,n);
        mpz_powm(h3,h3,d,n);
        mpz_powm(h4,h4,d,n);
       g0=mpz_get_ui(h0);
       g1=mpz_get_ui(h1);
       g2=mpz_get_ui(h2);
       g3=mpz_get_ui(h3);
       g4=mpz_get_ui(h4);   
        

        //calling the decrypt function to decrypt the cipher text packet and receiving the acknowledgement
      char ack=decrypt(d,n,g0,g1,g2,g3,g4);        
          
           //sending the acknowledgement
          if(send(new_fd,(char*)&ack,sizeof ack, 0) == -1)
               perror("send"); 
            //if the acknowledgement is y then receive process is continued else broken 
            if(ack=='y')
               continue;
            else break;
 

            

          }    
       close(new_fd);  // parent doesn't need this
         
        
    }
 flag=1;
//fclose(fp1);   
}
    
   //closing the socket
   close(sockfd);
    
    return 0;
}


/**************************the decrypt function**************************/
char decrypt(mpz_t d,mpz_t n,unsigned long int &g0,unsigned long int &g1,unsigned long int &g2,unsigned long int &g3,unsigned long int &g4){
        
       //opening the buffer file
        FILE *fp;
        if((fp=fopen("buffer","r"))==NULL){
        printf("cannot open file");
        exit(1);
        }
        
      //opening the output file
        FILE *fp2;
        if((fp2=fopen("output","a"))==NULL){
        printf("cannot open file");
        exit(1);
        }
      unsigned long int x,y,z1,w,v;
        mpz_t c; 
        mpz_init(c);
        //read c from the buffer
        mpz_inp_str(c,fp,10);
        mpz_t z;
         mpz_init(z);
        
        //decrypting c
        mpz_powm(z,c,d,n);
         
         
       //converting z to the actual message
        char mstr[151];
         for(int i=0;i<151;i++)
         mstr[i]='\0';
         mpz_get_str(mstr,10,z);
         char u[150],temp[150];
          for(int i=0;i<150;i++)
           u[i]='\0';  
         
          int i=0;
         if(mstr[0]=='3'||mstr[0]=='2'||mstr[0]=='4'||mstr[0]=='5'||mstr[0]=='6'||mstr[0]=='7'||mstr[0]=='8'||mstr[0]=='9')
         {u[0]='0'; 
          
         for(int j=1;j<151;j++)
         {u[j]=mstr[i];i++;}
         }
         else
         {for(int i=0;i<151;i++)
          u[i]=mstr[i];
         }
        
         char ack;
        //calling the SHA1 function 
        SHA1(u,x,y,z1,w,v);
       
        //checking the signatures received and the ones calculated 
        if(x==g0&&y==g1&&z1==g2&&w==g3&&v==g4)
        ack='y';
          else {return'n';
            }
             
            
           
         char ch[50];
         int a[50];
          for(int i=0;i<50;i++)
           {ch[i]='\0';
             a[i]=(int)ch;
           }
         int k=0,j=0;
          
         for(int i=0;i<50;i++)
           {
           if(mstr[j]=='\0')
            {
              a[i]=0;
             ch[k]='\0';
              k++; j++;
             continue;
            }
       else if(((int)mstr[j]-48)>=3&&(int)mstr[j]-48<=9)
         {
           a[i]=10*((int)mstr[j]-48)+((int)mstr[j+1]-48);
           j=j+2;}
       else
        {a[i]=100*((int)mstr[j]-48)+10*((int)mstr[j+1]-48)+((int)mstr[j+2]-48);
          j=j+3;
        }
       if((a[i]<32||a[i]>125)&&a[i]!=10)
       ch[k]=' ';
       else
       ch[k]=(char)a[i];
       //cout<<ch[k];
       k++;
      }

     int g=0;
     //writing the message into file
      while(ch[g]!='\0'&&g<50)
       {putc(ch[g],fp2);
        g++;
       }

//closing both the files
fclose(fp);
fclose(fp2);
//acknowledgement returned
return ack;
}

/*******************************SHA1 function***************************/
void SHA1(char * str1,unsigned long int &h0,unsigned long int &h1,unsigned long int &h2,unsigned long int &h3,unsigned long int &h4)
 {
     unsigned long int a,b,c,d,e,f,k,temp;
       
     h0 = 0x67452301;
     h1 = 0xEFCDAB89;
     h2 = 0x98BADCFE;
     h3 = 0x10325476;
    h4 = 0xC3D2E1F0;

     char str[251];
    for(int i=0;i<strlen(str);i++)
     str[i]='\0';
     strcpy((char *)str,(const char *)str1);
     
     
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
     //initialzing the number of chunks
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
 
