#include "headers.h"

#include "bits.h"
#include "cond.h"
#include "enums.h"
#include "node.h"
#include "policy.h"
#include "rules.h"

int main(void) {
  create_policy();

  if (fetch_bitstream() != 0) {
    return 1;
  }

  // Rule1
  metadata UNUSED meta_rule1 = {.src_ip = 3232235521,
                                .dst_ip = 2886729729,
                                .application = DPI_APP_FACEBOOK};

  // Rule2
  metadata UNUSED meta_rule2 = {.dst_ip = 202116108,
                                .dst_port = 8080,
                                .src_ip = 185273099,
                                .application = DPI_APP_FACEBOOK};

  // Rule3
  metadata UNUSED meta_rule3 = {
      .application = DPI_APP_YOUTUBE, .sub_protocol = 0, .src_ip = 84215046};

  // Rule4
  metadata UNUSED meta_rule4 = {
      .src_ip = 84215045, .application = DPI_APP_YOUTUBE, .src_port = 8086};

  evaluate_rules(&meta_rule4);

  free_streams();
  return 0;
}
