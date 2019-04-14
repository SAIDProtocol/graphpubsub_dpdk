/* 
 * File:   gps_i_neighbor_table.c
 * Author: Jiachen Chen
 *
 * Created on April 14, 2019, 2:53 AM
 */

#include "gps_i_neighbor_table.h"

struct rte_hash *gps_i_neighbor_keys;
struct gps_i_neighbor_info *gps_i_neighbor_values;
