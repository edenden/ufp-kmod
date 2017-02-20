# ufp-kmod
Kernel module for userspace driver

## 1. Background
This kernel module was included in [UFP](https://github.com/edenden/ufp).
The module in UFP is no longer used because UFP changed its kernel part function to VFIO now.
So this does not has value other than my reference uses.
Offcourse do not use it except for experimental purpose.
This contains following features:

* **PCI device information retrieving through ioctl()**
	* PCI vendor ID
	* PCI device ID
* **DMA mapping of user space memory through ioctl()**
	* support of Hugepages
	* support of both IOMMU and non-IOMMU environments.
* **device register mapping by mmap()**
* **interrupt notification**
	* support of MSI-X
	* eventfd can be bound through ioctl()
	* getting IRQ vector number through ioctl()
