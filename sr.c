#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include "emulator.h"
#include "sr.h"


#define RTT  16.0       /* round trip time.  MUST BE SET TO 16.0 when submitting assignment */
#define WINDOWSIZE 6    /* the maximum number of buffered unacked packet
                          MUST BE SET TO 6 when submitting assignment */
#define SEQSPACE 20    /* the min sequence space for GBN must be at least windowsize + 1 */
#define NOTINUSE (-1)   /* used to fill header fields that are not being used */

/* Global variables for sender (A) */
static struct pkt send_buffer[SEQSPACE];  /* buffer for sent packets */
static bool acked[SEQSPACE];                /* track ACK status for each seqnum */
static int base;                            /* first unACKed packet in window */
static int A_nextseqnum;                    /* next sequence number to use */

/* Global variables for receiver (B) */
static struct pkt rcv_buffer[SEQSPACE];   /* buffer for out-of-order packets */
static int expectedseqnum;                  /* next expected sequence number */                   

int ComputeChecksum(struct pkt packet)
{
  int checksum = 0;
  int i;

  checksum = packet.seqnum;
  checksum += packet.acknum;
  for ( i=0; i<20; i++ )
    checksum += (int)(packet.payload[i]);

  return checksum;
}

bool IsCorrupted(struct pkt packet)
{
  if (packet.checksum == ComputeChecksum(packet))
    return (false);
  else
    return (true);
}

/********* Sender (A) functions ************/

/* Helper function: Check if a given sequence number `numseq` is within the specified window range. It accounts for wrap-around using modulo arithmetic.*/
bool is_seq_in_window(int numseq, int windowbase, int windowsize, int seq_space) {
  int windowend = (windowbase + windowsize) % seq_space;
  if (windowbase < windowend) {
      return (numseq >= windowbase && numseq < windowend); /* straightforward case */
  } else {
      return (numseq >= windowbase || numseq < windowend);
  }
}

/* A_output: Called from layer 5 (application layer), passed the message to be sent to other side */
void A_output(struct msg message)
{
    struct pkt sendpkt;
    int i;
    
    int buffered_count = (A_nextseqnum - base + SEQSPACE) % SEQSPACE; /* Calculate mumber of packets in the window */

    if (buffered_count < WINDOWSIZE) { /* Check if the window is not full */
    
        sendpkt.seqnum = A_nextseqnum;
        sendpkt.acknum = NOTINUSE;
        /* Fill the payload with the message data */
        for (int i = 0; i < 20; i++) {
            sendpkt.payload[i] = message.data[i];
        }
        /* Compute and attach the checksum */
        sendpkt.checksum = ComputeChecksum(sendpkt); 
        send_buffer[A_nextseqnum % SEQSPACE] = sendpkt; /* Store the packet in the buffer */
        acked[A_nextseqnum % SEQSPACE] = false; /* Mark it as unacknowledged */

        /* Send the packet to layer 3 */
        if (TRACE > 0) printf("Sending packet %d to layer 3\n", sendpkt.seqnum);
        tolayer3(A, sendpkt);

        if (base == A_nextseqnum) { /* If this is the first packet in the window */
            starttimer(A, RTT); /* Start the timer */
        }

        A_nextseqnum = (A_nextseqnum + 1) % SEQSPACE;
    } else {
        if (TRACE > 0) printf("----A: New message arrives, send window is full\n");
        window_full++;
    }
}

void A_input(struct pkt packet) 
{
  /* Check if the received packet is corrupted */  
    if (IsCorrupted(packet)) {
      if (TRACE > 0) printf("----A: corrupted ACK is received, do nothing!\n");
      return;
  }
  /* Check if the received ACK is within the window range */
  if (TRACE > 0) printf("----A: uncorrupted ACK %d is received\n", packet.acknum);
  total_ACKs_received++;
  
  /* Check if the ACK is within the window range */
  /* The base is the first unacknowledged packet, and A_nextseqnum is the next sequence number to be sent */
  bool in_window = false;
  if (base <= A_nextseqnum) { /* Normal case: no wrap-around */
      in_window = (packet.acknum >= base && packet.acknum < A_nextseqnum);
  } else {
      in_window = (packet.acknum >= base || packet.acknum < A_nextseqnum);
  }

  if (!in_window) return;
  /* If the ACK is not in the window, ignore it */
  int ack_index = packet.acknum % SEQSPACE;

  /* Check if the ACK is a duplicate */
  if (acked[ack_index]) {
      if (TRACE > 0) printf("----A: duplicate ACK %d received, do nothing!\n", packet.acknum);
      return;
  }
  /* If it's a new ACK, mark it as acknowledged */
  if (TRACE > 0) printf("----A: ACK %d is not a duplicate\n", packet.acknum);
  acked[ack_index] = true;
  new_ACKs++;
  /* Update the base to the next unacknowledged packet */
  if (packet.acknum == base) {
      stoptimer(A);
      while (base != A_nextseqnum && acked[base % SEQSPACE]) { /* Move the base forward */
          acked[base % SEQSPACE] = false; /* clear flag for reuse*/
          base = (base + 1) % SEQSPACE;
      }
      /* Restart the timer if there are still unacknowledged packets*/
      if (base != A_nextseqnum) {
          starttimer(A, RTT);
      }
  }
}

/* A_timerinterrupt: Called when the timer expires. Resends the oldest unacknowledged packet.*/
void A_timerinterrupt(void)
{
  if (base == A_nextseqnum) return; /* Nothing to do if window is empty */

    int base_index = base % SEQSPACE;
    struct pkt base_packet = send_buffer[base_index];

    /* Resend the base packet */
    if (TRACE > 0) {
        printf("----A: time out, resend packet %d\n", base_packet.seqnum);
    }

    /* resend the packet at the base of the window */
    tolayer3(A, base_packet);
    packets_resent++;

    starttimer(A, RTT);
}

/*  A_init: Initialization function for sender A. Sets up initial values for sequence numbers and ACK tracking */
void A_init(void)
{
    A_nextseqnum = 0;
    base = 0;
    for (int i = 0; i < SEQSPACE; i++) {
        acked[i] = false;
    }
}

/* called from layer 3, when a packet arrives for layer 4 at B*/
void B_input(struct pkt packet)
{
  struct pkt sendpkt;
  int i;

  /* if not corrupted and received packet is in order */
  if  ( (!IsCorrupted(packet))  && (packet.seqnum == expectedseqnum) ) {
    if (TRACE > 0)
      printf("----B: packet %d is correctly received, send ACK!\n",packet.seqnum);
    packets_received++;

    /* deliver to receiving application */
    tolayer5(B, packet.payload);

    /* send an ACK for the received packet */
    sendpkt.acknum = expectedseqnum;

    /* update state variables */
    expectedseqnum = (expectedseqnum + 1) % SEQSPACE;
  }
  else {
    /* packet is corrupted or out of order resend last ACK */
    if (TRACE > 0)
      printf("----B: packet corrupted or not expected sequence number, resend ACK!\n");
    if (expectedseqnum == 0)
      sendpkt.acknum = SEQSPACE - 1;
    else
      sendpkt.acknum = expectedseqnum - 1;
  }

  /* create packet */
  sendpkt.seqnum = B_nextseqnum;
  B_nextseqnum = (B_nextseqnum + 1) % 2;

  /* we don't have any data to send.  fill payload with 0's */
  for ( i=0; i<20 ; i++ )
    sendpkt.payload[i] = '0';

  /* computer checksum */
  sendpkt.checksum = ComputeChecksum(sendpkt);

  /* send out packet */
  tolayer3 (B, sendpkt);
}

/* the following routine will be called once (only) before any other */
/* entity B routines are called. You can use it to do any initialization */
void B_init(void)
{
  expectedseqnum = 0;
  B_nextseqnum = 1;
}

/******************************************************************************
 * The following functions need be completed only for bi-directional messages *
 *****************************************************************************/

/* Note that with simplex transfer from a-to-B, there is no B_output() */
void B_output(struct msg message)
{
}

/* called when B's timer goes off */
void B_timerinterrupt(void)
{
}
