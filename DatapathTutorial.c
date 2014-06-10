/*
 *------------------------------------------------------------------
 * onePK SDK Tutorials
 *
 * DatapathTutorial.c
 *
 * Copyright (c) 2012-2013 by Cisco Systems, Inc.
 *
 * THIS SAMPLE CODE IS PROVIDED "AS IS" WITHOUT ANY EXPRESS OR IMPLIED WARRANTY
 * BY CISCO SOLELY FOR THE PURPOSE of PROVIDING PROGRAMMING EXAMPLES.
 * CISCO SHALL NOT BE HELD LIABLE FOR ANY USE OF THE SAMPLE CODE IN ANY
 * APPLICATION.
 *
 * Redistribution and use in source or binary forms, with or without
 * modification, is subject to the terms and conditions of the Cisco onePK
 * Software Development Kit License Agreement (onePK SDK Internal User License).
 *------------------------------------------------------------------
 */


/*
 * This tutorial demonstrates onepk Datapath Service Set.
 * This tutorial will show you how to add a hook into the packet
 * flow through a Cisco switch or router and extract packets from
 * that flow of packets.
 *
 * There are some pre-requisites to running this tutorial which are mentioned in
 * the README file of this tutorial
 *
 */
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <unistd.h>

#include "onep_core_services.h"
#include "onep_policy_bulk.h"
#include "onep_datapath_policy.h"
#include "onep_class.h"
#include "onep_filter.h"
#include "onep_dpss_packet_delivery.h"
#include "onep_types.h"
#include "onep_dpss_actions.h"
#include "onep_dpss_pkt.h"
#include "onep_dpss_flow.h"
#include "onep_dpss_callback_framework.h"

#include "session_element_util.h"
#include "include/datapath_util.h"
#define FAIL false
#define SUCCESS true
#define DPSS_ACTION_MAX_LEN (20)

static onep_network_element_t*  ne = NULL;
onep_policy_global_cap_t *global_cap = NULL;
onep_policy_cap_filter_t *filter_cap = NULL;
onep_collection_t *tables = NULL;
static int proto;

// START SNIPPET: callback_info
/*
 * Extract the IP version from a packet.
 */
onep_status_t dpss_tutorial_get_ip_version(struct onep_dpss_paktype_ *pakp,
    char *ip_version) {

    onep_status_t rc;
    uint16_t l3_protocol;
    char l3_prot_sym = 'U';

    /* Get packet L3 protocol. */
    rc = onep_dpss_pkt_get_l3_protocol(pakp, &l3_protocol);
    if( rc == ONEP_OK ) {
        if( l3_protocol == ONEP_DPSS_L3_IPV4 ) {
            l3_prot_sym = '4';
        } else if( l3_protocol == ONEP_DPSS_L3_IPV6 ) {
            l3_prot_sym = '6';
        } else if( l3_protocol == ONEP_DPSS_L3_OTHER ) {
            l3_prot_sym = 'N';
        } else {
            l3_prot_sym = 'U';
        }
    } else {
        fprintf(stderr, "Error getting L3 protocol. code[%d], text[%s]\n",
              rc, onep_strerror(rc));
        return (rc);
    }
    *ip_version = l3_prot_sym;
    return (ONEP_OK);
}


/*
 * Extract IP addressing and port information from the packet.
 */
onep_status_t dpss_tutorial_get_ip_port_info(
    struct onep_dpss_paktype_ *pakp, char **src_ip, char **dest_ip,
    uint16_t *src_port, uint16_t *dest_port, char *prot, char ip_version ) {

    onep_status_t   rc;
    uint8_t         l4_protocol;
    uint8_t         *l3_start;
    struct iphdr    *l3hdr;
    uint8_t         *l4_start;
    struct tcphdr   *l4tcp;
    struct udphdr   *l4udp;

    if( ip_version == '4' ) {
        /* get IPv4 header */
        rc = onep_dpss_pkt_get_l3_start(pakp, &l3_start);
        if( rc==ONEP_OK ) {
            l3hdr = (struct iphdr *)l3_start; // convert to iphdr
            *src_ip = strdup(inet_ntoa( *(struct in_addr *)&(l3hdr->saddr) ));
            *dest_ip = strdup(inet_ntoa( *(struct in_addr *)&(l3hdr->daddr) ));
        } else {
            fprintf(stderr,"Error getting IPv4 header. code[%d], text[%s]\n",
                  rc, onep_strerror(rc));
            return (ONEP_ERR_SYSTEM);
        }
    } else if( ip_version == '6' ) {
        fprintf(stderr, "Cannot get IPv6 traffic at this time.\n");
        return (ONEP_ERR_SYSTEM);
    } else if( ip_version == 'N' ) {
        fprintf(stderr, "IP address is neither IPv4 nor IPv6.\n");
        return (ONEP_ERR_SYSTEM);
    } else {
        fprintf(stderr, "Unknown IP version.\n");
        return (ONEP_ERR_SYSTEM);
    }

    /* get L4 header */
    rc = onep_dpss_pkt_get_l4_start(pakp, &l4_start);
    if( rc != ONEP_OK ) {
        fprintf(stderr, "Error getting L4 header. code[%d], text[%s]\n",
              rc, onep_strerror(rc));
        return (rc);
    }

    /* get packet L4 protocol */
    rc = onep_dpss_pkt_get_l4_protocol(pakp, &l4_protocol);
    if( rc == ONEP_OK ) {
        if( l4_protocol == ONEP_DPSS_TCP_PROT ) {
            /* TCP */
            strcpy(prot,"TCP");
            l4tcp = (struct tcphdr *)l4_start;
            *src_port = ntohs( l4tcp->source );
            *dest_port = ntohs( l4tcp->dest );
        }
        else if( l4_protocol == ONEP_DPSS_UDP_PROT ) {
            /* UDP */
            strcpy(prot,"UDP");
            l4udp = (struct udphdr *)l4_start;
            *src_port = ntohs( l4udp->source );
            *dest_port = ntohs( l4udp->dest );
        }
        else if( l4_protocol == ONEP_DPSS_ICMP_PROT ) {
            strcpy(prot,"ICMP");
        }
        else if( l4_protocol == ONEP_DPSS_IPV6_ENCAPSULATION_PROT ) {
            // sends IPV6 packet as payload of IPV4
            strcpy(prot,"ENCP"); // IPV6 encapsulated on IPV4
        }
        else {
            strcpy(prot,"UNK!"); // Unknown!
        }
    }
    else {
        fprintf(stderr, "Error getting L4 protocol. code[%d], text[%s]\n",
              rc, onep_strerror(rc));
    }
    return (ONEP_OK);
}


/*
 * Extract some flow state given a packet and a FID.
 */
void dpss_tutorial_get_flow_state(struct onep_dpss_paktype_ *pakp,
    onep_dpss_flow_ptr_t fid, char *l4_state_char ) {

    onep_status_t             rc;
    onep_dpss_l4_flow_state_e l4_state;

    rc = onep_dpss_flow_get_l4_flow_state(pakp,&l4_state);
    if( rc==ONEP_OK ) {
        if( l4_state == ONEP_DPSS_L4_CLOSED ) {
            strcpy(l4_state_char,"CLOSED");
        } else if( l4_state == ONEP_DPSS_L4_OPENING ) {
            strcpy(l4_state_char,"OPENING");
        } else if( l4_state == ONEP_DPSS_L4_UNI_ESTABLISHED ) {
            strcpy(l4_state_char,"UNI-ESTABLISHED");
        } else if( l4_state == ONEP_DPSS_L4_UNI_ESTABLISHED_INCORRECT ) {
            strcpy(l4_state_char,"UNI-ESTABLISHED INCORRECT");
        } else if( l4_state == ONEP_DPSS_L4_BI_ESTABLISHED ) {
            strcpy(l4_state_char,"BI-ESTABLISHED");
        } else if( l4_state == ONEP_DPSS_L4_BI_ESTABLISHED_INCORRECT ) {
            strcpy(l4_state_char,"BI-ESTABLISHED INCORRECT");
        } else if( l4_state == ONEP_DPSS_L4_CLOSING ) {
            strcpy(l4_state_char,"CLOSING");
        } else {
            strcpy(l4_state_char,"!UNKNOWN!");
        }
    } else {
        fprintf(stderr, "Error getting L4 state of flow. code[%d], text[%s]\n",
              rc, onep_strerror(rc));
    }
    return;
}

/*
 * Simple packet callback that will just display some information per
 * packet. Can be used for diverted or copied packets and doesn't try to
 * take any action on the packet.
 */
void dpss_display_pak_info_callback(onep_dpss_traffic_reg_t *reg,
    struct onep_dpss_paktype_ *pak, void *client_context, bool *return_packet) {
	
	static int count = 1;   /* packet counter*/

    onep_status_t        rc;
    onep_dpss_fid_t      fid;
    char                 ipv = 0;
    uint16_t             src_port = 0;
    uint16_t             dest_port = 0;
    char                 *src_ip = NULL;
    char                 *dest_ip = NULL;
    char                 l4_protocol[5];
    char                 l4_state[30];

    strcpy(l4_protocol,"ERR");
    strcpy(l4_state,"ERR");

    rc = onep_dpss_pkt_get_flow(pak, &fid);
    if( rc == ONEP_OK ) {
        rc = dpss_tutorial_get_ip_version(pak, &ipv);
        if( rc != ONEP_OK ) {
            fprintf(stderr, "Error in get ip version: code[%d], text[%s]\n",
                    rc, onep_strerror(rc));
        }
        rc = dpss_tutorial_get_ip_port_info(pak, &src_ip,
                                            &dest_ip,
                                            &src_port,
                                            &dest_port,
                                            l4_protocol,
                                            ipv);
        if( rc != ONEP_OK ) {
          fprintf(stderr, "Error in get ip port info: code[%d], text[%s]\n",
                  rc, onep_strerror(rc));
        }
        dpss_tutorial_get_flow_state(pak, fid, l4_state);

    } else {
        fprintf(stderr, "Error getting flow ID. code[%d], text[%s]\n",
              rc, onep_strerror(rc));
    }
    printf(
        "\n"
        "\033[22;4;30m"
        "| FID | IPv | Source                  |"
        " Destination             | Prot | Pkt# | State                     |\n"
        "\033[0m");
    printf(
      "| %-3"PRIu64" |  %c  | %-15s : %-5d | %-15s : %-5d | %-4s | %3d  | %-25s |\n\n",
      fid, ipv, src_ip, src_port, dest_ip, dest_port,
      l4_protocol,count, l4_state);
    count++;
    free(src_ip);
    free(dest_ip);
    return;
}
// END SNIPPET: callback_info

/*
 * Display a list of interfaces.
 */
void dpss_tutorial_display_intf_list(onep_collection_t *intf_list, FILE *op)
{
    onep_status_t rc;
    unsigned int count;
    onep_network_interface_t* intf;
    onep_if_name name;

    onep_collection_get_size(intf_list, &count);
    if (count>0) {
        unsigned int i;
        for (i = 0; i < count; i++) {
            rc = onep_collection_get_by_index(intf_list, i, (void *)&intf);
            if (rc==ONEP_OK) {
                rc = onep_interface_get_name(intf,name);
                fprintf(op, "[%d] Interface [%s]\n", i, name);
            } else {
               fprintf(stderr, "Error getting interface. code[%d], text[%s]\n",
               rc, onep_strerror(rc));
            }
        }
    }
}

// START SNIPPET: get_table
/*
 *   Get traffic action table
 */
onep_status_t dpss_tutorial_find_datapath_table(
    onep_network_element_t *elem,
    onep_policy_table_cap_t **table_cap)
{
    onep_status_t rc = ONEP_OK;
    uint32_t table_count = 0;

    /* Get traffic action table */
    rc = onep_policy_get_global_capabilities(ne, &global_cap);
   if (rc != ONEP_OK) {
      fprintf(stderr, "Error in get global cap: %s\n\n", onep_strerror(rc));
      return rc;
   }

   rc = onep_policy_cap_filter_new(&filter_cap);
   if (rc != ONEP_OK) {
      fprintf(stderr, "Error in cap filter: %s\n", onep_strerror(rc));
      return rc;
   }

   rc = onep_policy_cap_filter_add_table_type(filter_cap, ONEP_POLICY_TABLE_TYPE_DATAPATH);
   if (rc != ONEP_OK) {
      fprintf(stderr, "Error in cap filter type: %s\n", onep_strerror(rc));
      return rc;
   }

   rc = onep_policy_global_cap_get_table_list(global_cap, filter_cap, &tables);
   if (rc != ONEP_OK) {
      fprintf(stderr, "Error in getting table list: %s\n", onep_strerror(rc));
      return rc;
   }

   rc = onep_collection_get_size(tables, &table_count);
    if(rc != ONEP_OK) {
      fprintf(stderr, "\nError in get cap table size : %d, %s\n",
            rc, onep_strerror(rc));
      return rc;
   }

    /*
     * Need to have >0 datapath tables
     */
    if (table_count==0) {
      printf("table count = 0\n");
      return ONEP_FAIL;
    }

    /*
     * Get the first table
     */
    rc = onep_collection_get_by_index(tables, 0, (void **)table_cap);
    if(rc != ONEP_OK) {
      fprintf(stderr, "\nError in get table by index : %d, %s\n",
            rc, onep_strerror(rc));
      return rc;
    }
    return rc;
}
// END SNIPPET: get_table

// START SNIPPET: get_class
/*
 * Example function to create a simple ACL and Policy Map
 */
onep_status_t dpss_tutorial_create_ip_pmap (
    onep_network_element_t *elem,
    onep_dpss_pak_callback_t callback,
    onep_dpss_pkt_action_type_e action,
    onep_policy_pmap_handle_t *pmap_handle,
    onep_acl_t ** acl)
{
    onep_ace_t *ace40 = 0;
    onep_acl_t *onep_acl = 0;
    onep_collection_t *result_list = 0;
    onep_iterator_t *iter = 0;
    onep_policy_action_holder_t *ah = 0;
    onep_policy_action_t *dp_action = 0;
    onep_policy_cmap_handle_t cmap_handle;
    onep_policy_cmap_op_t *cmap_op = 0;
    onep_policy_entry_op_t *entry_op;
    onep_policy_match_holder_t *mh = 0;
    onep_policy_match_t *match = 0;
    onep_policy_op_list_t *op_list = 0;
    onep_policy_pmap_op_t *pmap_op = 0;
    onep_policy_table_cap_t *table_cap = 0;
    onep_status_t rc = ONEP_OK;
    onep_status_t destroy_rc = ONEP_OK;

    /* create a simple ACL, ip any any */
    rc = onep_acl_create_l3_acl(AF_INET, elem, &onep_acl);
    if(rc != ONEP_OK) {
      fprintf(stderr, "\nError in onep_acl_create_l3_acl: %d, %s\n",
            rc, onep_strerror(rc));
      return rc;
   }

   //Create ACE40(seq=40, permit)
    rc = onep_acl_create_l3_ace(40, TRUE, &ace40);
    if(rc != ONEP_OK) {
      fprintf(stderr, "\nError in onep_acl_create_l3_ace: %d, %s\n",
            rc, onep_strerror(rc));
      goto cleanup;
   }

   //Set ACE40 src prefix
    rc = onep_acl_set_l3_ace_src_prefix(ace40, NULL, 0);
    if(rc != ONEP_OK) {
      fprintf(stderr, "\nError in onep_acl_set_l3_ace_src_prefix : %d, %s\n",
            rc, onep_strerror(rc));
      goto cleanup;
   }

   //Set ACE40 dest prefix
    rc = onep_acl_set_l3_ace_dst_prefix(ace40, NULL, 0);
    if(rc != ONEP_OK) {
      fprintf(stderr, "\nError in onep_acl_set_l3_ace_dst_prefix: %d, %s\n",
            rc, onep_strerror(rc));
      goto cleanup;
   }

   //Set ACE40 dest port
    rc = onep_acl_set_l3_ace_protocol(ace40, proto);
    if(rc != ONEP_OK) {
      fprintf(stderr, "\nError in onep_acl_set_l3_ace_protocol: %d, %s\n",
            rc, onep_strerror(rc));
      goto cleanup;
   }

   //Set ACE40 src port
    rc = onep_acl_set_l3_ace_src_port(ace40, 0, ONEP_COMPARE_ANY);
    if(rc != ONEP_OK) {
      fprintf(stderr, "\nError in onep_acl_set_l3_ace_src_port: %d, %s\n",
            rc, onep_strerror(rc));
      goto cleanup;
   }

   //Set ACE40 dest port
    rc = onep_acl_set_l3_ace_dst_port(ace40, 0, ONEP_COMPARE_ANY);
    if(rc != ONEP_OK) {
      fprintf(stderr, "\nError in onep_acl_set_l3_ace_dst_port: %d, %s\n",
            rc, onep_strerror(rc));
      goto cleanup;
   }

   //Add ACE40 to ACL
   rc = onep_acl_add_ace(onep_acl, ace40);
   if(rc != ONEP_OK) {
      fprintf(stderr, "\nError in onep_acl_add_ace: %d, %s\n",
            rc, onep_strerror(rc));
      goto cleanup;
   }

   /*
    * Get traffic action table
    */
    rc = dpss_tutorial_find_datapath_table(elem, &table_cap);
    if(rc != ONEP_OK) {
      goto cleanup;
    }

    /*
     * Create a class based on the ACL.
     */

    /* 1. Create the op_list */
    rc = onep_policy_cmap_op_list_new(&op_list);
    if(rc != ONEP_OK) {
      fprintf(stderr, "\nError in onep_policy_cmap_op_list_new: %d, %s\n",
               rc, onep_strerror(rc));
      goto cleanup;
    }

    /* 2. Add the network element */
    rc = onep_policy_op_add_network_element(op_list, elem);
    if(rc != ONEP_OK) {
         fprintf(stderr, "\nError in onep_policy_op_add_network_element: %d, %s\n",
               rc, onep_strerror(rc));
         goto cleanup;
    }

    /* 3. Create a specific operation on the list */
    rc = onep_policy_cmap_op_create(op_list, table_cap, &cmap_op);
    if(rc != ONEP_OK) {
         fprintf(stderr, "\nError in onep_policy_cmap_op_create: %d, %s\n",
               rc, onep_strerror(rc));
         goto cleanup;
    }

    /* 4. Get the match holder for the operation instance */
    rc = onep_policy_cmap_op_get_match_holder(cmap_op, &mh);
    if(rc != ONEP_OK) {
      fprintf(stderr, "\nError in onep_policy_cmap_op_get_match_holder: %d, %s\n",
            rc, onep_strerror(rc));
      goto cleanup;
    }

    /* 5. Add an access list match */
    rc = onep_policy_match_add_access_list( mh, (onep_policy_access_list_t *)onep_acl, &match);
    if(rc != ONEP_OK) {
      fprintf(stderr, "\nError in onep_policy_match_add_access_list: %d, %s\n",
            rc, onep_strerror(rc));
      goto cleanup;
    }

    /* 6. Submit the operation. */
    rc = onep_policy_op_update(op_list);
    if(rc != ONEP_OK) {
      fprintf(stderr, "\nError in onep_policy_op_update: %d, %s\n",
            rc, onep_strerror(rc));
      goto cleanup;
    }

    /* 7. Find the cmap_handle we just created */
    rc = onep_policy_op_list_get_list(op_list, &result_list);
    if(rc != ONEP_OK) {
         fprintf(stderr, "\nError in onep_policy_op_list_get_list: %d, %s\n",
               rc, onep_strerror(rc));
         goto cleanup;
    }

    rc = onep_collection_get_iterator(result_list, &iter);
    if(rc != ONEP_OK) {
         fprintf(stderr, "\nError in onep_collection_get_iterator: %d, %s\n",
               rc, onep_strerror(rc));
         goto cleanup;
    }
    cmap_op = (onep_policy_cmap_op_t *)onep_iterator_next(iter);
    if (!cmap_op) {
      fprintf(stderr, "\nError in getting policy op\n");
      goto cleanup;
    }

    rc = onep_policy_cmap_op_get_handle(cmap_op, &cmap_handle);
    if(rc != ONEP_OK) {
      fprintf(stderr, "\nError in creating class map : %d, %s\n",
            rc, onep_strerror(rc));
      goto cleanup;
    }

    /* 8. Destroy the op list */
    rc = onep_policy_op_list_destroy(&op_list);
    if(rc != ONEP_OK) {
         fprintf(stderr, "\nError in onep_policy_op_list_destroy: %d, %s\n",
               rc, onep_strerror(rc));
         goto cleanup;
    }

    /*
     * Create a policy using the class just created.
     */

    /* 1. Create the op_list */
    rc = onep_policy_pmap_op_list_new(&op_list);
    if(rc != ONEP_OK) {
      fprintf(stderr, "\nError in onep_policy_pmap_op_list_new: %d, %s\n",
            rc, onep_strerror(rc));
      goto cleanup;
    }

    /* 2. Add the network element */
    rc = onep_policy_op_add_network_element(op_list, elem);
    if(rc != ONEP_OK) {
      fprintf(stderr, "\nError in onep_policy_op_add_network_element: %d, %s\n",
            rc, onep_strerror(rc));
      goto cleanup;
    }

    /* 3. Add pmap create operation to list */
    rc = onep_policy_pmap_op_create(op_list, table_cap, &pmap_op);
    if(rc != ONEP_OK) {
      fprintf(stderr, "\nError in onep_policy_pmap_op_create: %d, %s\n",
            rc, onep_strerror(rc));
      goto cleanup;
    }

    /* 4. Add an entry */
    rc = onep_policy_pmap_op_entry_insert_sequence(pmap_op, 200, &entry_op);
    if(rc != ONEP_OK) {
      fprintf(stderr, "\nError in onep_policy_pmap_op_entry_insert_sequence: %d, %s\n",
            rc, onep_strerror(rc));
      goto cleanup;
    }

    /* 5. Set the cmap on the entry */
    rc = onep_policy_entry_op_add_cmap(entry_op, cmap_handle);
    if(rc != ONEP_OK) {
      fprintf(stderr, "\nError in onep_policy_entry_op_add_cmap: %d, %s\n",
            rc, onep_strerror(rc));
      goto cleanup;
    }

    /* 6. Try and add an action */
    rc = onep_policy_entry_op_get_action_holder(entry_op, &ah);
    if(rc != ONEP_OK) {
      fprintf(stderr, "\nError in onep_policy_entry_op_get_action_holder: %d, %s\n",
            rc, onep_strerror(rc));
      goto cleanup;
    }

    if (action==ONEP_DPSS_ACTION_COPY) {
      printf ("Adding ONEP DPSS Action Copy\n");
      rc = onep_policy_action_add_copy(ah, callback, NULL, &dp_action);
      if(rc != ONEP_OK) {
         fprintf(stderr, "\nError in onep_policy_action_add_copy: %d, %s\n",
               rc, onep_strerror(rc));
         goto cleanup;
      }
    } else if ((action==ONEP_DPSS_ACTION_PUNT)||(action==ONEP_DPSS_ACTION_DIVERT)) {
      printf ("adding  action on punt and divert\n");
      rc = onep_policy_action_add_divert(ah, callback, NULL, &dp_action);
      if(rc != ONEP_OK) {
         fprintf(stderr, "\nError in onep_policy_action_add_divert: %d, %s\n",
               rc, onep_strerror(rc));
         goto cleanup;
      }
      if (action==ONEP_DPSS_ACTION_PUNT) {
          rc = onep_policy_action_set_stateful(dp_action);
          if(rc != ONEP_OK) {
               fprintf(stderr, "\nError in onep_policy_action_set_stateful: %d, %s\n",
                         rc, onep_strerror(rc));
               goto cleanup;
          }
                
      }

    }

    /* 7. Submit the operation. */
    rc = onep_policy_op_update(op_list);
    if(rc != ONEP_OK) {
       fprintf(stderr, "\nError in onep_policy_op_update: %d, %s\n",
             rc, onep_strerror(rc));
       goto cleanup;
    }

    /* 8. Find the pmap_handle we just created */
    rc = onep_policy_op_list_get_list(op_list, &result_list);
    if(rc != ONEP_OK) {
      fprintf(stderr, "\nError in onep_policy_op_list_get_list: %d, %s\n",
            rc, onep_strerror(rc));
      goto cleanup;
    }

    rc = onep_collection_get_iterator(result_list, &iter);
    if(rc != ONEP_OK) {
      fprintf(stderr, "\nError in onep_collection_get_iterator: %d, %s\n",
            rc, onep_strerror(rc));
      goto cleanup;
    }

    pmap_op = (onep_policy_pmap_op_t *)onep_iterator_next(iter);
    if (!pmap_op) {
      fprintf(stderr, "Error in getting pmap_op\n");
      rc = ONEP_FAIL;
      goto cleanup;
     }

    rc = onep_policy_pmap_op_get_handle(pmap_op, pmap_handle);
    if(rc != ONEP_OK) {
      fprintf(stderr, "\nError in onep_policy_pmap_op_get_handle: %d, %s\n",
            rc, onep_strerror(rc));
      goto cleanup;
    }

    /* Return the acl we created */
   *acl = onep_acl;
   printf("Successfully created acl.\n");
   printf("Done creating policy handle.\n");

   cleanup:
         destroy_rc = onep_policy_op_list_destroy(&op_list);
         if(destroy_rc != ONEP_OK) {
           fprintf(stderr, "\nError in onep_policy_op_list_destroy: %d, %s\n",
               destroy_rc, onep_strerror(destroy_rc));
         }
   return rc;
}
// END SNIPPET: get_class

/* Main application  */
int main (int argc, char* argv[]) {
   onep_session_handle_t* sh;
   uint64_t pak_count, last_pak_count = 0;
   int timeout = 60;
   int loop_count = 1;
   unsigned int count = 0;
   onep_status_t       rc;
   onep_status_t destroy_rc;

   // START SNIPPET: c_variables
   onep_interface_filter_t* intf_filter = NULL;
   onep_collection_t*  intfs = NULL;
   onep_if_name intf_name;
   onep_policy_pmap_handle_t pmap_handle = 0;
   onep_policy_op_list_t *op_list = NULL;
   onep_policy_target_op_t *target_op = NULL;
   onep_dpss_pkt_action_type_e the_action;
   onep_acl_t * acl = NULL;
   char action[DPSS_ACTION_MAX_LEN];
   onep_dpss_pak_callback_t the_callback_handler;
   // END SNIPPET: c_variables

   /* validate and parse the input. */
   if (parse_options_datapath(argc, argv) == 1) {
      fprintf(stderr, "Usage: %s %s %s %s %s\n",
         argv[0],
         get_usage_required_options(),
         get_usage_required_options_datapath(),
         get_usage_optional_options_datapath(),
         get_usage_optional_options());
      return EXIT_FAILURE;
   }

   if (strcasecmp(get_transport_type(), "tipc") != 0
      || strcmp(get_transport_type(), "2") != 0) {
      prompt_authentication();
      prompt_client_key_passphrase();
   }
   
   proto = atoi(get_protocol());
   strncpy(action, get_action(), DPSS_ACTION_MAX_LEN - 1);
   strncpy(intf_name, get_interface(), ONEP_IF_NAME_SIZE - 1);

   /* Connect to the Network Element */
   sh = connect_network_element(
               get_element_hostname(),
               get_login_username(),
               get_login_password(),
               "com.cisco.onepapp.datapath",
               get_transport_type(),
               &ne);

   if (!sh) {
      fprintf(stderr, "\n*** create_network_connection fails ***\n");
      return ONEP_FAIL;
   }
    printf("\n Network Element CONNECT SUCCESS \n");

     // START SNIPPET: get_interface
     /*
      * Get list of interfaces on device, then find the interface we want.
      */
     rc = onep_interface_filter_new(&intf_filter);
     if (rc != ONEP_OK) {
         fprintf(stderr, "\nError creating intf filter. code[%d], text[%s]\n",
                 rc, onep_strerror(rc));
         goto cleanup;
     }
     rc = onep_element_get_interface_list(ne, intf_filter, &intfs);
     if (rc != ONEP_OK) {
        fprintf(stderr, "\nError getting interface. code[%d], text[%s]\n",
                rc, onep_strerror(rc));
        goto cleanup;
     }
     rc = onep_collection_get_size(intfs, &count);
     if (rc != ONEP_OK) {
         fprintf(stderr, "\nError getting interface. code[%d], text[%s]\n",
                 rc, onep_strerror(rc));
         goto cleanup;
     }
     if (count <= 0 ) {
        fprintf(stderr, "\nNo interfaces available");
        goto cleanup;
     }
    // END SNIPPET: get_interface

    /*
     * Display the interfaces we retrieved
     */
    dpss_tutorial_display_intf_list(intfs,stderr);

    /*
     * Register some packet handlers.
     */
   onep_network_interface_t *intf;
   printf("\n Name of interface expecting packets: %s\n", intf_name);
   rc = onep_element_get_interface_by_name(ne, intf_name, &intf);
   if (rc != ONEP_OK) {
      fprintf(stderr, "Error in getting interface: %s\n", onep_strerror(rc));
      goto cleanup;
   }

   //START SNIPPET: register_packets
   /*
   * Policy action copy - copy packet to DPSS and forward the original.
   * Application is not allowed to modify the packet or return the packet.
   * 
   * Policy action punt/divert - packet sent to DPSS app and does not continue on 
   * it's original path
   */
   if (strcmp(action,"copy") == 0)
       the_action = ONEP_DPSS_ACTION_COPY;
   else if(strcmp(action,"divert") == 0)
	   the_action = ONEP_DPSS_ACTION_DIVERT;
   else if(strcmp(action,"punt") == 0)
	   the_action = ONEP_DPSS_ACTION_PUNT;
   else
	   the_action = ONEP_DPSS_ACTION_COPY;
   /* Callback function for processing packets.*/
   the_callback_handler = dpss_display_pak_info_callback;

   /* create a simple ACL and onep Policy map */
   rc = dpss_tutorial_create_ip_pmap(ne,
          the_callback_handler,
          the_action,
          &pmap_handle,
          &acl);
   if(rc != ONEP_OK) {
      goto cleanup;
   }

   /*
    * Now we have a policy, we're going to activate it on one
    * interface
    *
    * So, first create a target operation list and set the network
    * element on it.
    */
   printf ("Applying policy on interface %s\n", intf_name);
   rc = onep_policy_target_op_list_new(&op_list);
   if(rc != ONEP_OK) {
      fprintf(stderr, "\nError in onep_policy_target_op_list_new: %d, %s",
            rc, onep_strerror(rc));
      goto cleanup;
   }

   rc = onep_policy_op_add_network_element(op_list, ne);
   if(rc != ONEP_OK) {
      fprintf(stderr, "\nError in onep_policy_op_add_network_element: %d, %s",
            rc, onep_strerror(rc));
      goto cleanup;
   }

   /* Add request to bind policy to interface */
   rc = onep_policy_target_op_activate(op_list, &target_op);
   if(rc != ONEP_OK) {
      fprintf(stderr, "\nError in onep_policy_target_op_activate: %d, %s",
            rc, onep_strerror(rc));
      goto cleanup;
   }
   rc = onep_policy_target_op_add_pmap(target_op, pmap_handle);
   if(rc != ONEP_OK) {
      fprintf(stderr, "\nError in onep_policy_target_op_add_pmap: %d, %s",
            rc, onep_strerror(rc));
      goto cleanup;
   }

   rc = onep_policy_target_op_add_interface(target_op, intf);
   if(rc != ONEP_OK) {
      fprintf(stderr, "\nError in onep_policy_target_op_add_interface: %d, %s",
            rc, onep_strerror(rc));
      goto cleanup;
   }
   rc = onep_policy_target_op_set_direction(target_op, ONEP_DIRECTION_IN);
   if(rc != ONEP_OK) {
      fprintf(stderr, "\nError in onep_policy_target_op_set_direction: %d, %s",
            rc, onep_strerror(rc));
      goto cleanup;
   }
   printf ("Finished applying policy on interface\n");
   //END SNIPPET: register_packets

   rc = onep_policy_op_update(op_list);
   if(rc != ONEP_OK) {
      fprintf(stderr, "\nError in onep_policy_op_update: %d, %s",
            rc, onep_strerror(rc));
      goto cleanup;
   }

   last_pak_count = 0;
   /* wait to query the packet loop for the number
    * of packets received and processed. */
   printf ("\n\nWaiting for packets...\n");
   while (loop_count < 3) {
      sleep(timeout);
      (void) onep_dpss_packet_callback_rx_count(&pak_count);
      fprintf(stderr, "Current Packet Count: %"PRIu64"\n", pak_count);
      if (pak_count == last_pak_count) {
        break;
      } else {
        last_pak_count = pak_count;
        loop_count++;
      }
   }

   printf("\nDone. Goodbye!");
   printf("\n\n******* DISCONNECT AND CLEAN UP *******\n\n");

   cleanup:
      if(op_list != NULL && target_op != NULL) {
         destroy_rc =  onep_policy_target_op_deactivate(op_list, &target_op);
         if(destroy_rc != ONEP_OK) {
            fprintf(stderr, "\nError in onep_policy_target_op_deactivate: %d, %s",
                destroy_rc, onep_strerror(destroy_rc));
         }
      } 
      if(op_list) {
         destroy_rc = onep_policy_op_list_destroy(&op_list);
         if(destroy_rc != ONEP_OK) {
            fprintf(stderr, "\nError in onep_policy_op_list_destroy: %d, %s",
                destroy_rc, onep_strerror(destroy_rc));
         }
      }
      if(acl) {
         destroy_rc = onep_acl_delete_acl(&acl);
         if(destroy_rc != ONEP_OK) {
            fprintf(stderr, "\nError in onep_acl_delete_acl: %d, %s",
                destroy_rc, onep_strerror(destroy_rc));
         }
      }
      if(global_cap) {
         destroy_rc = onep_policy_global_cap_destroy(&global_cap);
         if(destroy_rc != ONEP_OK) {
            fprintf(stderr, "\nError in onep_policy_global_cap_destroy: %d, %s",
                destroy_rc, onep_strerror(destroy_rc));
         }
      }
      if(filter_cap) {
         destroy_rc = onep_policy_cap_filter_destroy(&filter_cap);
         if(destroy_rc != ONEP_OK) {
            fprintf(stderr, "\nError in onep_policy_cap_filter_destroy: %d, %s",
               destroy_rc, onep_strerror(destroy_rc));
         }
      }
      if(tables) {
         destroy_rc = onep_collection_destroy(&tables);
         if(destroy_rc != ONEP_OK) {
            fprintf(stderr, "\nError in destroy tables : %d, %s",
               destroy_rc, onep_strerror(destroy_rc));
         }
      }
      if(intfs) {
         destroy_rc = onep_collection_destroy(&intfs);
         if(destroy_rc != ONEP_OK) {
             fprintf(stderr, "\nError in destroy intfs : %d, %s",
                 destroy_rc, onep_strerror(destroy_rc));
         }
      }
      if(intf_filter) {
         destroy_rc = onep_interface_filter_destroy(&intf_filter);
         if(destroy_rc != ONEP_OK) {
             fprintf(stderr, "\nError in destroy intf_filter : %d, %s",
                 destroy_rc, onep_strerror(destroy_rc));
         }
      }

   return rc;
}


