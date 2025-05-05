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
  int window_end = (windowbase + windowsize) % seq_space;
  if (windowbase < window_end) {
      return (numseq >= windowbase && numseq < window_end); /* straightforward case */
  } else {
      return (numseq >= windowbase || numseq < window_end);
  }
}

/* A_output: Called from layer 5 (application layer), passed the message to be sent to other side */
void A_output(struct msg message)
{
  struct pkt sendpkt;
  int i;
  int buffered_count; /* Number of packets in the send window */
  /* Check if the sender is blocked waiting for an ACK */
  /* The sender is blocked if the number of buffered packets is equal to the window size */
  buffered_count = (A_nextseqnum - base + SEQSPACE) % SEQSPACE;
  
  /* If there is space in the send window, proceed to create and send the packet */
  if (buffered_count < WINDOWSIZE)
  {
    if (TRACE > 1) printf("----A: New message arrives, send window is not full, send new message to layer3!\n");

    sendpkt.seqnum = A_nextseqnum;
    sendpkt.acknum = NOTINUSE; /* No need to send an ACK number from A */
    for (i = 0; i < 20; i++) sendpkt.payload[i] = message.data[i]; /* Copy the message data into the packet payload */
    sendpkt.checksum = ComputeChecksum(sendpkt);

    send_buffer[A_nextseqnum % SEQSPACE] = sendpkt;
    acked[A_nextseqnum % SEQSPACE] = false;

    if (TRACE > 0) printf("Sending packet %d to layer 3\n", sendpkt.seqnum);
    tolayer3(A, sendpkt);

    if (base == A_nextseqnum) { /* If this is the first packet in the window, start the timer */
        starttimer(A, RTT);
    }

    A_nextseqnum = (A_nextseqnum + 1) % SEQSPACE;
  }
  else
  {
    if (TRACE > 0) printf("----A: New message arrives, send window is full\n");
    window_full++;
  }
}

void A_input(struct pkt packet) 
{
  int ack_index;
  bool in_win_flag = false;
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
  
  if (base <= A_nextseqnum) { /* Normal case: no wrap-around */
      in_win_flag = (packet.acknum >= base && packet.acknum < A_nextseqnum);
  } else {
      in_win_flag = (packet.acknum >= base || packet.acknum < A_nextseqnum);
  }

  if (!in_win_flag) {
    return;
  }
  /* If the ACK is not in the window, ignore it */
  ack_index = packet.acknum % SEQSPACE;

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
  int base_index;
  struct pkt base_packet;
  if (base == A_nextseqnum) {
    return;
  } /* Nothing to do if window is empty */

  base_index = base % SEQSPACE;
  base_packet = send_buffer[base_index];

    /* Resend the base packet */
  if (TRACE > 0) {
    printf("----A: time out,resend packets!\n");
    printf("---A: resending packet %d\n", base_packet.seqnum);
  }

    /* resend the packet at the base of the window */
  tolayer3(A, base_packet);
  packets_resent++;

  starttimer(A, RTT);
}

/*  A_init: Initialization function for sender A. Sets up initial values for sequence numbers and ACK tracking */
void A_init(void)
{
    int i;
    A_nextseqnum = 0;
    base = 0;
    for (i = 0; i < SEQSPACE; i++) {
        acked[i] = false;
    }
}

/********* Receiver (B) functions ************/
void B_input(struct pkt packet)
{
  struct pkt ackpkt;
  int i;
  int buffer_index;
  bool in_recv_window; /* Check if the packet is in the receive window */
  bool in_lower_window; /* Check if the packet is in the lower window */
  /* Check if the received packet is corrupted */
  /* If the packet is corrupted, ignore it and do not send an ACK */
  if (IsCorrupted(packet)) {
    return;
  }


  if (TRACE > 0) printf("----B: packet %d is correctly received, send ACK!\n",packet.seqnum);
  packets_received++;
  /* The expected sequence number is the next expected packet */
  in_recv_window = is_seq_in_window(packet.seqnum, expectedseqnum, WINDOWSIZE, SEQSPACE);
  in_lower_window = is_seq_in_window(packet.seqnum, (expectedseqnum - WINDOWSIZE + SEQSPACE) % SEQSPACE, WINDOWSIZE, SEQSPACE);


  if (in_recv_window) {
      /* If the packet is in the receive window, send an ACK */
      ackpkt.seqnum = NOTINUSE; /* No need to send a sequence number in the ACK */
      ackpkt.acknum = packet.seqnum;  /* ACK the received packet */
      for (i = 0; i < 20; i++) ackpkt.payload[i] = '0'; /* Fill the payload with dummy data */
      ackpkt.checksum = ComputeChecksum(ackpkt);
      tolayer3(B, ackpkt);  /* Send the ACK to layer 3 */

      buffer_index = packet.seqnum % SEQSPACE; /* Calculate the index in the receive buffer */
      if (rcv_buffer[buffer_index].seqnum == NOTINUSE) {
          rcv_buffer[buffer_index] = packet; /* Store the received packet in the buffer */

          /* Check if there are any packets in the buffer that can be delivered */
          while (rcv_buffer[expectedseqnum % SEQSPACE].seqnum != NOTINUSE) {
              tolayer5(B, rcv_buffer[expectedseqnum % SEQSPACE].payload); /* Deliver the packet to layer 5 */
              rcv_buffer[expectedseqnum % SEQSPACE].seqnum = NOTINUSE;  /* Mark slot as free*/
              expectedseqnum = (expectedseqnum + 1) % SEQSPACE; /* Update the expected sequence number */
          }
      }
      return;
  }

  if (in_lower_window) {
      /* If the packet is in the lower window, send an ACK for the last received packet */
      /* This is a duplicate packet, so we resend the last ACK */
      ackpkt.seqnum = NOTINUSE;
      ackpkt.acknum = packet.seqnum; 
      for (i = 0; i < 20; i++) ackpkt.payload[i] = '0';
      ackpkt.checksum = ComputeChecksum(ackpkt);
      tolayer3(B, ackpkt);
      return;
  }

  return;
}
  

void B_init(void)
{
  /* initialise receive buffer to empty state*/
  int i;
  expectedseqnum = 0;
  for (i = 0; i < SEQSPACE; i++) {
        rcv_buffer[i].seqnum = NOTINUSE;
    }
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
