/* SPDX-License-Identifier: GPL-2.0 */
static const char *__doc__ = "Simple XDP prog doing XDP_PASS\n";

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <net/if.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */

#include "../common/common_params.h"

static const struct option_wrapper long_options[] = {
    {{"help", no_argument, NULL, 'h'},
    "Show help", false},
    
    {{"dev", required_argument, NULL, 'd'},
    "Operate on device <ifname>", "<ifname>", true},

    {{"skb-mode", no_argument, NULL, 'S'},
    "Install XDP program in SKB(AKA generic) mode"},

    {{"native-mode", no_argument, NULL, 'N'},
    "Install XDP program in native mode"},

    {{"auto-mode", no_argument, NULL, 'A'},
    "Auto-detect SKB or native mode"},

    {{"force", no_argument, NULL, "F"},
    "Force install ,replacing existing program on interface"},

    {{"unload", no_argument, NULL, "U"},
    "Unload XDP program intead of loading"},

    {{0, 0, NULL, 0},}
}

static int xdp_link_detach(int ifindex, __u32 xdp_flags){
    return 0;
}



int main(int argc, char **argv){
    struct bpf_prog_info info = {};
    __u32 info_len = sizeof(info);
    //需要加载进内核的文件
    char filename[256] = "xdp_pass_kern.o";
    int prog_fd, err;

    struct config cfg = {
        .xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE,
        .ifindex = -1,
        .do_unload = false;
    };


    parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);
    //required option
    if(cfg.ifindex == -1){
        fprintf(stderr, "ERR: required option --dev missing\n");
		usage(argv[0], __doc__, long_options, (argc == 1));
		return EXIT_FAIL_OPTION;
    }
    if(cfg.co_unload)
        return xdp_link_detach(cfg.ifindex, cfg.xdp_flags);
    
}