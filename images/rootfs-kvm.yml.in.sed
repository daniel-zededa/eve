kernel:
  image: KERNEL_TAG
  cmdline: "rootdelay=3"
init:
  - linuxkit/init:8f1e6a0747acbbb4d7e24dc98f97faa8d1c6cec7
  - linuxkit/runc:f01b88c7033180d50ae43562d72707c6881904e4
  - linuxkit/containerd:de1b18eed76a266baa3092e5c154c84f595e56da
  - linuxkit/getty:v0.5
  - linuxkit/memlogd:v0.5
  - DOM0ZTOOLS_TAG
  - GRUB_TAG
  - FW_TAG
  - XEN_TAG
  - GPTTOOLS_TAG
onboot:
   - name: rngd
     image: RNGD_TAG
     command: ["/sbin/rngd", "-1"]
   - name: sysctl
     image: linuxkit/sysctl:v0.5
     binds:
        - /etc/sysctl.d:/etc/sysctl.d
     capabilities:
        - CAP_SYS_ADMIN
        - CAP_NET_ADMIN
   - name: modprobe
     image: linuxkit/modprobe:v0.5
     command: ["/bin/sh", "-c", "modprobe -a nct6775 w83627hf_wdt hpwdt wlcore_sdio wl18xx br_netfilter dwc3 rk808 rk808-regulator smsc75xx cp210x nicvf tpm_tis_spi rtc_rx8010 gpio_pca953x leds_siemens_ipc127 upboard-fpga pinctrl-upboard leds-upboard xhci_tegra 2>/dev/null || :"]
   - name: storage-init
     image: STORAGE_INIT_TAG
services:
   - name: newlogd
     image: NEWLOGD_TAG
     cgroupsPath: /eve/services/newlogd
     oomScoreAdj: -999
   - name: edgeview
     image: EDGEVIEW_TAG
     cgroupsPath: /eve/services/eve-edgeview
     oomScoreAdj: -800
   - name: debug
     image: DEBUG_TAG
     cgroupsPath: /eve/services/debug
     oomScoreAdj: -999
   - name: wwan
     image: WWAN_TAG
     cgroupsPath: /eve/services/wwan
     oomScoreAdj: -999
   - name: wlan
     image: WLAN_TAG
     cgroupsPath: /eve/services/wlan
     oomScoreAdj: -999
   - name: guacd
     image: GUACD_TAG
     cgroupsPath: /eve/services/guacd
     oomScoreAdj: -999
   - name: pillar
     image: PILLAR_TAG
     cgroupsPath: /eve/services/pillar
     oomScoreAdj: -999
   - name: vtpm
     image: VTPM_TAG
     cgroupsPath: /eve/services/vtpm
     oomScoreAdj: -999
   - name: watchdog
     image: WATCHDOG_TAG
     cgroupsPath: /eve/services/watchdog
     oomScoreAdj: -1000
   - name: xen-tools
     image: XENTOOLS_TAG
     cgroupsPath: /eve/services/xen-tools
     oomScoreAdj: -999
files:
   - path: /etc/eve-release
     contents: 'EVE_VERSION'
   - path: etc/linuxkit-eve-config.yml
     metadata: yaml
