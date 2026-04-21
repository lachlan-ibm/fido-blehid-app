# Device Kernel & USB Gadget Research

**Device:** OPPO CPH2735
**SoC:** MediaTek MT6835
**Build type:** `user` (production, non-rooted)

---

## Kernel Modules

All modules are compiled into the kernel image and loaded at boot. No `.ko` files exist on the filesystem — there are no dynamically loadable modules available to install or `insmod`.

The full loaded module list (from `/proc/modules`) covers the following categories:

| Category | Key modules |
|---|---|
| Wireless / BT / GPS | `wlan_drv_gen4m_6835`, `bt_drv_connac1x`, `gps_drv_stp`, `fmradio_drv_mt6631_6635`, `wmt_drv` |
| Display | `mediatek_drm`, `mali_kbase_mt6835`, `ged`, `mtk_mml` |
| Camera | `imgsensor_isp6s`, `camera_isp`, `camera_dip_isp6s`, `camera_fdvt_isp51` |
| Audio | `snd_soc_mt6835_afe`, `snd_soc_mt6377`, `audio_ipi`, `adsp` |
| USB | `mtu3`, `xhci_mtk_hcd_v2`, `mtk_usb_f_rndis`, `tcpc_class` |
| Charging / Power | `oplus_chg`, `mt6375_battery`, `mt6377_battery`, `mtk_low_battery_throttling` |
| CPU / Scheduler | `scheduler`, `cpufreq_uag`, `cpufreq_sugov_ext`, `oplus_bsp_sched_assist`, `oplus_bsp_frame_boost` |
| Security / TEE | `gz_trusty_mod`, `mcDrvModule`, `trusted_mem`, `widevine_driver` |
| Storage | `ufs_mediatek_mod`, `mtk_mmc`, `rpmb_mtk` |
| Thermal | `thermal_interface`, `soc_temp_lvts`, `mtk_lpm` |
| NFC | `nfc_i2c`, `sn_ese`, `oplus_nfc` |
| Touchscreen | `gt9895`, `oplus_bsp_tp_comon`, `oplus_bsp_tp_custom` |
| OPLUS BSP | `oplus_bsp_*` (memory, scheduler, sensor, TP, IR, zram, etc.) |

---

## Modules Relevant to This Project

### `udev`

**Not available.** Not loaded, not present as a `.ko` file.

Android does not use `udev`. Device event handling is performed by `ueventd`, a built-in component of the Android `init` process. It is not a kernel module and cannot be replaced or supplemented with `udev`.

### `vhci_hcd` (USB/IP virtual HCI)

**Not available.** Not loaded, not present as a `.ko` file.

`vhci_hcd` is the kernel module that provides the USB/IP host-side virtual HCI — it allows a remote USB device to appear as a local USB device over a network connection. This kernel was not compiled with USB/IP support (`CONFIG_USBIP_VHCI_HCD` is absent), so this approach is not viable on this device.

---

## USB Gadget / Software USB Device Emulation

The kernel was compiled with USB ConfigFS gadget support. ConfigFS is mounted at `/config` (type `configfs`).

### Compiled-in gadget functions (from `CONFIG_*`)

| Config option | Status | Description |
|---|---|---|
| `CONFIG_USB_GADGET` | `y` | Core USB gadget framework |
| `CONFIG_USB_CONFIGFS` | `y` | ConfigFS-based gadget configuration |
| `CONFIG_USB_CONFIGFS_F_HID` | `y` | HID gadget function |
| `CONFIG_USB_CONFIGFS_F_FS` | `y` | FunctionFS (userspace gadget) |
| `CONFIG_USB_CONFIGFS_F_UVC` | `y` | USB Video Class gadget |
| `CONFIG_USB_CONFIGFS_F_MIDI` | `y` | MIDI gadget |
| `CONFIG_USB_CONFIGFS_F_UAC2` | `y` | USB Audio Class 2 gadget |
| `CONFIG_USB_CONFIGFS_ACM` | `y` | ACM serial gadget |
| `CONFIG_USB_CONFIGFS_NCM` | `y` | NCM network gadget |
| `CONFIG_USB_CONFIGFS_MASS_STORAGE` | `y` | Mass storage gadget |
| `CONFIG_USB_DUMMY_HCD` | **not set** | Software-only loopback HCD (no physical USB needed) |
| `CONFIG_USB_RAW_GADGET` | **not set** | Raw gadget interface |
| `CONFIG_USB_GADGETFS` | **not set** | Legacy gadgetfs |
| `CONFIG_USB_G_HID` | **not set** | Legacy HID gadget (non-ConfigFS) |

### Summary of emulation options

| Approach | Kernel support | Root required | Viable on this device |
|---|---|---|---|
| ConfigFS + `f_hid` (HID gadget over physical USB) | Yes | Yes | Only with root |
| ConfigFS + FunctionFS `f_ffs` (userspace gadget) | Yes | Yes (for setup) | Only with root |
| `USB_DUMMY_HCD` (pure software, no physical USB) | No | — | No |
| `USB_RAW_GADGET` | No | — | No |
| `vhci_hcd` / USB-IP | No | — | No |

### Root constraint

This is a production build (`ro.build.type=user`, `ro.debuggable=0`). `adbd` refuses to run as root:

```
adbd cannot run as root in production builds
```

Writing to `/config/usb_gadget/` requires root. Without it, the only USB gadget functions exposed are those managed by the Android USB HAL (ADB, MTP, PTP).

To use `CONFIG_USB_CONFIGFS_F_HID` for a custom HID gadget (e.g. a FIDO USB HID authenticator), the device would need:

1. An unlocked bootloader with a rooted system image (e.g. Magisk), **or**
2. A custom engineering/debug firmware build (`ro.debuggable=1`)

---

## Implications for This Project

The [`HIDService`](../app/src/main/java/com/isfs/blekey/hidsvc/HIDService.java) in this project implements FIDO HID over **BLE** (Bluetooth Low Energy), not USB HID. The BLE transport does not depend on any of the USB gadget infrastructure above.

If USB HID transport were to be added in future (to present the device as a USB FIDO authenticator to a connected host), it would require:

- Root access to configure the `f_hid` gadget via ConfigFS
- Writing HID reports to `/dev/hidg0` (created by the `f_hid` function)
- A physical USB connection to the host (the device acts as USB peripheral)

This is architecturally different from the current BLE HID approach and is not supported on unrooted production devices.